# pylint: disable=broad-except
# - Specific exception not generated on lopy
# pylint: disable=import-error
# - Module paths fixed at upload by Makefile

'''
SCHC compressor, Copyright (c) <2017><IMT Atlantique and Philippe Clavier>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

    This file presents a simple CoAP client using SCHC compression to send
    and receive packets over LoRa.
'''

import socket
import time
import struct
from binascii import unhexlify

from network import LoRa

import CoAP

from SCHC.RuleMngt import RuleManager
from SCHC.Parser import Parser
from SCHC.Compressor import Compressor

# Select the rule you want to test here
#from rules import RULE_NO_COMPRESSION as compression_rule
from rules import RULE_COMPRESS_IPV6 as compression_rule
#from rules import RULE_COMPRESS_IPV6_UDP as compression_rule
#from rules import RULE_COMPRESS_ALL as compression_rule

IPV6_SOURCE = unhexlify("FE80:0000:0000:0000:0000:0000:0000:0001".replace(':', ''))
IPV6_DEST = unhexlify("FE80:0000:0000:0000:0000:0000:0000:0002".replace(':', ''))

LORA = LoRa(mode=LoRa.LORAWAN)
RM = RuleManager()
RM.addRule(compression_rule)

PARSER = Parser()
COMP = Compressor(RM)

APP_EUI = unhexlify('00 00 00 00 00 00 00 00'.replace(' ', ''))
APP_KEY = unhexlify('11 22 33 44 55 66 77 88 11 22 33 44 55 66 77 88'.replace(' ', ''))

# join a network using OTAA (Over the Air Activation)
LORA.join(activation=LoRa.OTAA, auth=(APP_EUI, APP_KEY), timeout=0)

# wait until the module has joined the network
while not LORA.has_joined():
    time.sleep(2.5)
    print('Not yet joined...')

# create a LoRa socket
LORA_SOCKET = socket.socket(socket.AF_LORA, socket.SOCK_RAW)# pylint: disable=no-member
                                                           # - Lora socket specific options
LORA_SOCKET.bind(0x02)

# set the LoRaWAN data rate
LORA_SOCKET.setsockopt(socket.SOL_LORA, socket.SO_DR, 5) # pylint: disable=no-member
LORA_SOCKET.setsockopt(socket.SOL_LORA, socket.SO_CONFIRMED, False) # pylint: disable=no-member

def make_ipudp_buffer(ips, ipd, source_port, destination_port, ulp):
    """ Generates a buffer containing the IPv6 and UDP layer of a packet """
    retval = struct.pack('!HHHBB', 0x6000, 0x0000, len(ulp) + 8, 17, 30) + \
    ips + \
    ipd + \
    struct.pack("!HHHH", source_port, destination_port, len(ulp) + 8, 0x0000) + \
    ulp

    return retval

def compress_and_send():
    """ Compresses and sends dummy data """
    coap_message = CoAP.Message()

    coap_message.new_header(type=CoAP.CON, code=CoAP.POST, midSize=4, token=0x82)
    coap_message.add_option_path('foo')
    coap_message.add_option_path('bar')
    coap_message.end_option()

    ipv6 = make_ipudp_buffer(IPV6_SOURCE, IPV6_DEST, 5682, 5555, coap_message.buffer)

    fields, data = PARSER.parser(ipv6)
    rule = COMP.RuleMngt.FindRuleFromHeader(fields, "up")
    if rule != None:
        result = struct.pack('!B', rule["ruleid"]) # start with the ruleid
        res = COMP.apply(fields, rule["content"], "up")
        res.add_bytes(data)
        result += res.buffer()

        print("Compressed Header = ", result)

        LORA_SOCKET.setblocking(True)
        LORA_SOCKET.settimeout(10)
        try:
            LORA_SOCKET.send(result)
        except Exception as exception:
            print("TIMEOUT in sending : " + str(exception))

        try:
            data = LORA_SOCKET.recv(64)
            data_available = True
        except Exception as exception:
            print('timeout in receive' + str(exception))
            data_available = False

        LORA_SOCKET.setblocking(False)

        if data_available:
            print("receive DATA", data)

while True:
    compress_and_send()
    time.sleep(30)
