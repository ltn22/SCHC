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
'''

SIGFOX = False
LORAWAN = True

if LORAWAN:
    from network import LoRa
if SIGFOX:
    from network import Sigfox

import socket
import time
import binascii
import pycom
#import _thread
from binascii import hexlify
#import struct
import gc

print ('MEM', gc.mem_free())

import CoAP
from CBOR import CBOR

gc.collect()

from RuleMngt import RuleManager
from Parser import Parser
from Compressor import Compressor
from Decompressor import Decompressor

from machine import I2C
from BMP280 import BMP280

IPv6_source = binascii.unhexlify("200104701f1209f2000000000000000b".replace (':', ''))
IPv6_dest   = binascii.unhexlify("200141d0040131000000000000003682".replace (':', ''))


#                           fID                  Pos  DI  TV                  MO           CDA
rule_coap0 = {"ruleid"  : 0,
             "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
                          ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
                          ["IPv6.flowLabel",    1,  "bi", 0x000000,           "equal",  "not-sent"],
                          ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                          ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
                          ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
                          ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
                          ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
                          ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                          ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                          ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "bi", 0,                  "equal", "not-sent"],
                          ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "bi", 2,                  "equal", "not-sent"],
                          ["CoAP.messageID",    1,  "bi", 1,                  "MSB(4)", "LSB"],
                          ["CoAP.token",        1,  "bi", 0x01,               "MSB(4)", "LSB"],
                          ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
                          ["CoAP.Uri-Path",     2,  "up", "bar",              "ignore", "value-sent"],
                       ]}

rule_coap1 = {"ruleid"  : 1,
             "content" : [["IPv6.version",      1,  "bi", 6,                  "equal", "not-sent"],
                          ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal", "not-sent"],
                          ["IPv6.flowLabel",    1,  "bi", 0x000000,           "ignore", "not-sent"],
                          ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                          ["IPv6.nextHeader",   1,  "bi", 17,                 "equal", "not-sent"],
                          ["IPv6.hopLimit",     1,  "bi", 30,                 "equal", "not-sent"],
                          ["IPv6.prefixES",     1,  "bi", 0x200104701f1209f2, "equal", "not-sent"],
                          ["IPv6.iidES",        1,  "bi", 0x000000000000000b, "equal", "not-sent"],
                          ["IPv6.prefixLA",     1,  "bi", [0xFE80000000000000,
                                                           0x2001123456789012,
                                                           0x200104701f1209f2,
                                                           0x200141d004013100],"match-mapping", "mapping-sent"],
                          ["IPv6.iidLA",        1,  "bi", 0x0000000000003682, "equal", "not-sent"],
                          ["UDP.PortES",        1,  "bi", 5684,               "equal", "not-sent"],
                          ["UDP.PortLA",        1,  "bi", 5684,               "equal", "not-sent"],
                          ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                          ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                          ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
                          ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                          ["CoAP.messageID",    1,  "bi", 0,                  "MSB(12)", "LSB"],
                          ["CoAP.token",        1,  "bi", 0x80,               "MSB(4)", "LSB"],
                          ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
                          ["CoAP.Uri-Path",     2,  "up", "bar",              "equal", "not-sent"],
                          ["CoAP.Uri-Path",     3,  "up", None,               "ignore", "value-sent"],
                          ["CoAP.Content-Format",1, "dw", None,               "ignore", "value-sent"],
                          ["CoAP.Uri-Query",    1,  "up", "k=",               "MSB(16)", "LSB"],
                          ["CoAP.Option-End",   1,  "up", 0xFF,               "equal", "not-sent"]
                       ]}

rule_coap2 = {"ruleid"  : 2,
             "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
                          ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
                          ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
                          ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                          ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
                          ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
                          ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
                          ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
                          ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                          ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                          ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "up", CoAP.CON,           "equal", "not-sent"],
                          ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
                          ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                          ["CoAP.messageID",    1,  "bi", 0,                  "MSB(12)", "LSB"],
                          ["CoAP.token",        1,  "bi", 0x80,               "MSB(5)", "LSB"],
                          ["CoAP.Uri-Path",     1,  "up", "measure",                "equal", "not-sent"],
                          ["CoAP.Option-End",   1,  "up", 0xFF,               "equal", "not-sent"]
                       ]}

#print ('MEM', gc.mem_free())


BMP280_REGISTER_TEMPDATA           = 0xFA

i2c = I2C(0, I2C.MASTER, baudrate=100000)
print('In I2C bus:',  i2c.scan())


#bmp = BMP280(i2c)

print ('MEM', gc.mem_free())

if LORAWAN:
    lora = LoRa(mode=LoRa.LORAWAN)
if SIGFOX:
    sigfox = Sigfox(mode=Sigfox.SIGFOX, rcz=Sigfox.RCZ1)


RM = RuleManager()
RM.addRule (rule_coap0)
RM.addRule (rule_coap1)
RM.addRule (rule_coap2)

p = Parser()
comp = Compressor(RM)
dec  = Decompressor(RM)
coapC = CoAP.CoAPSM(p, comp, dec, IPv6_source, IPv6_dest)


app_eui = binascii.unhexlify('00 00 00 00 00 00 00 00'.replace(' ',''))
app_key = binascii.unhexlify('11 22 33 44 55 66 77 88 11 22 33 44 55 66 77 88'.replace(' ',''))

pycom.heartbeat(False)


if LORAWAN:
    mac = lora.mac()
    print ('MAC:')
    print(hex(mac[0]), end='-')
    print(hex(mac[1]), end='-')
    print(hex(mac[2]), end='-')
    print(hex(mac[3]), end='-')
    print(hex(mac[4]), end='-')
    print(hex(mac[5]), end='-')
    print(hex(mac[6]), end='-')
    print(hex(mac[7]))


    for i in range (0,  255):
        led = i<< 16| i <<8  | i
        pycom.rgbled(led)
        time.sleep(0.01)

    # join a network using OTAA (Over the Air Activation)
    lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key),  timeout=0)

    # wait until the module has joined the network
    while not lora.has_joined():
        time.sleep(2.5)
        print('Not yet joined...')

    # create a LoRa socket
    s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
    s.bind(0x02);

    # set the LoRaWAN data rate
    s.setsockopt(socket.SOL_LORA, socket.SO_DR, 5)
    s.setsockopt(socket.SOL_LORA,  socket.SO_CONFIRMED,  False)

    print("apres setsock")
    # make the socket blocking
    # (waits for the data to be sent and for the 2 receive windows to expire)

if SIGFOX:
    # create a Sigfox socket
    s = socket.socket(socket.AF_SIGFOX, socket.SOCK_RAW)

    # make the socket blocking
    s.setblocking(True)

    # configure it as DOWNLINK specified by 'True'
    s.setsockopt(socket.SOL_SIGFOX, socket.SO_RX, True)


# send some data
rpd = 0.0
pd = 0.0



while True:
    try:
        (rp,  press,  temp) = bmp.getValue(0)
        print ('{0:8.2f}{1:8.2f}{2:8.2f} '.format(rp,  press,  temp))
    except:
        print('ERROR')
        temp = -1
        press = -1


    c = CBOR ([CBOR(int(temp*100)),  CBOR(int(press*100))])

    m = CoAP.Message()

    m.new_header(type=CoAP.CON,  code=CoAP.POST, midSize=4,  token=0x82)
    # for rule1
    # m.add_option_path('foo')
    # m.add_option_path('bar')
    # m.add_option_path('ABCD==')
    # m.add_option_query('k=eth0')

    # for rule_coap2
    m.add_option_path('measure')
    m.end_option()
    m.add_value(c)

    coapC.send(s, m)

    coapC.sleep (120)
