import struct
import socket
import time

from  SCHC import BitBuffer 

import CoAP

from SCHC.RuleMngt import RuleManager
from SCHC.Parser import Parser
from SCHC.Compressor import Compressor

from rules import RULE_COMPRESS_COAP as compression_rule

UDP_IP="192.168.1.158"
UDP_PORT=5683


RM = RuleManager()
RM.addRule(compression_rule)

PARSER = Parser()
COMP = Compressor(RM)


def compress_and_send():
    """ compress only coap part""" 
    coap_message = CoAP.Message()
    coap_message.new_header(type=CoAP.NON, code=CoAP.POST, midSize=4, token=0x82)
    coap_message.add_option_path(b'temperature')
    ##coap_message.add_option_proxyuri(b'coap://[2001:db8:0:f102::1]:5683')
    coap_message.end_option()

    print("Coap message size",len(coap_message.buffer))

    fields, data=  PARSER.parser(coap_message.buffer,protocol="coap")
    rule = COMP.RuleMngt.FindRuleFromHeader(fields, "up")
    data =b'T=30.4'

    if rule !=None: 
        result = struct.pack('!B', rule["ruleid"]) # start with the ruleid
        res = COMP.apply(fields, rule["content"], "up")
        res.add_bytes(data)
        result +=res.buffer()
        print("Compressed Header = ", result)

#result=struct.pack( '!B', 28)
#buf = BitBuffer.BitBuffer()
#data =b'T=30.4'
#buf.add_bytes(data)
#result+=buf.buffer()
        sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(result, (UDP_IP, UDP_PORT))



while True:
    compress_and_send()
    time.sleep(30)
