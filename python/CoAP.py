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

#from network import LoRa
import socket
import pycom
import struct
from CBOR import CBOR
import time
import binascii
import sys



CON = 0
"""Confirmable message type."""

NON = 1
"""Non-confirmable message type."""

ACK = 2
"""Acknowledgement message type."""

RST = 3
"""Reset message type"""

# types = {0: 'CON',
#          1: 'NON',
#          2: 'ACK',
#          3: 'RST'}

EMPTY = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
# CREATED = 65
# DELETED = 66
# VALID = 67
# CHANGED = 68
# CONTENT = 69
# CONTINUE = 95
# BAD_REQUEST = 128
# UNAUTHORIZED = 129
# BAD_OPTION = 130
# FORBIDDEN = 131
# NOT_FOUND = 132
# METHOD_NOT_ALLOWED = 133
# NOT_ACCEPTABLE = 134
# REQUEST_ENTITY_INCOMPLETE = 136
# PRECONDITION_FAILED = 140
# REQUEST_ENTITY_TOO_LARGE = 141
# UNSUPPORTED_CONTENT_FORMAT = 143
# INTERNAL_SERVER_ERROR = 160
# NOT_IMPLEMENTED = 161
# BAD_GATEWAY = 162
# SERVICE_UNAVAILABLE = 163
# GATEWAY_TIMEOUT = 164
# PROXYING_NOT_SUPPORTED = 165

# requests = {1: 'GET',
#             2: 'POST',
#             3: 'PUT',
#             4: 'DELETE'}

# requests_rev = {v:k for k, v in requests.items()}
#
# IF_MATCH = 1
# URI_HOST = 3
# ETAG = 4
# IF_NONE_MATCH = 5
# OBSERVE = 6
# URI_PORT = 7
# LOCATION_PATH = 8
# URI_PATH = 11
# CONTENT_FORMAT = 12
# MAX_AGE = 14
# URI_QUERY = 15
# ACCEPT = 17
# LOCATION_QUERY = 20
# BLOCK2 = 23
# BLOCK1 = 27
# SIZE2 = 28
# PROXY_URI = 35
# PROXY_SCHEME = 39
# SIZE1 = 60
#
# options = {1: 'If-Match',
#            3: 'Uri-Host',
#            4: 'ETag',
#            5: 'If-None-Match',
#            6: 'Observe',
#            7: 'Uri-Port',
#            8: 'Location-Path',
#            11: 'Uri-Path',
#            12: 'Content-Format',
#            14: 'Max-Age',
#            15: 'Uri-Query',
#            17: 'Accept',
#            20: 'Location-Query',
#            23: 'Block2',
#            27: 'Block1',
#            28: 'Size2',
#            35: 'Proxy-Uri',
#            39: 'Proxy-Scheme',
#            60: 'Size1'}
#
# options_rev = {v:k for k, v in options.items()}

mid = 1

class MsgInWait:

    def __init__(self, s, m, c, p):

        self.msg = m
        self.period = p
        self.timeout = p + time.time()
        self.DR = 5 # Data rate = 5 Best Perf
        self.attempts = 0
        self.socket = s
        self.comprimed = c

        print (binascii.hexlify(self.comprimed))

def increase_lora_delivary_chances(element):
    if (element.attempts == 2): element.DR = 4
    elif (element.attempts == 4): element.DR = 2

    element.socket.setsockopt(socket.SOL_LORA, socket.SO_DR, element.DR)

increase_delivary_chances_functions = {
  "LORAWAN": increase_lora_delivary_chances,
  "SIGFOX": lambda el: None,
}

class CoAPSM:

    def __init__ (self, p, c, d, ipv6s, ipv6d,  idcf):
        self.toBeAcked = []
        self.parser = p
        self.comp   = c
        self.dec    = d
        self.IPv6_source = ipv6s
        self.IPv6_dest   = ipv6d
        self.increase_delivary_chances = idcf

    def send(self,  sock,  msg,  timeout=0):
        print ("TIME= ", time.time(),  end =" ")
        print ("ADD ",  msg.mid,  end=' ')
        print ('IN ',  timeout)

        IPv6 = self.IP_UDP(self.IPv6_source,  self.IPv6_dest,  5682,  5683,  msg.buffer)

        print (IPv6)
        print (binascii.hexlify(IPv6))
        fields, data = self.parser.parser(IPv6)
        print (fields)
        rule = self.comp.RuleMngt.FindRuleFromHeader (fields, "up")
        print (rule)
        if (rule != None):
            result = struct.pack('!B', rule["ruleid"]) # start with the ruleid
            res =            self.comp.apply(fields, rule["content"], "up")
            print("compressed = ", binascii.hexlify(res.buffer()))
            res.add_bytes(data)
            result += res.buffer()

            print("Compressed Header = ", result)

            self.toBeAcked.append(MsgInWait(sock, msg, result,  timeout))

    def acked (self,  a):
        for m in self.toBeAcked:
            print (m,  '==>', m.msg.mid())
            print (a.mid())
            if (m.msg.mid() == a.mid()):
                self.toBeAcked.remove(m)

    def sleep(self,  duration):

        finishIn = time.time() + duration

        print('managing retransmission until TIME =',  finishIn)
        print (len(self.toBeAcked),  " waiting in Queue")

        while (time.time() + 30 < finishIn):
            if (len(self.toBeAcked) > 0):
            # find the next message to be acked
                when = duration;
                element = self.toBeAcked[0]
                for m in self.toBeAcked:
                    print ('time=',  time.time(),  end=' ')
                    print ("when =",  when,  end=" ")
                    print ("Mid = ",  m.msg.mid(),  end=" ")
                    print ('timeout = ',  m.timeout,  " diff = ",  m.timeout - time.time())

                    if (m.timeout < element.timeout): element = m

                print ("process ",  element.timeout)

                if (element.msg.type() == NON):
                    #No ack remove from the list
                    self.acked(element.msg)

                if element.attempts > 0:
                    self.increase_delivary_chances(element)

                element.socket.setblocking(True)
                element.socket.settimeout(10)

                print("sending: ", end="")
                print(binascii.hexlify(element.comprimed), end=' ')
                print(len(element.comprimed), " bytes ", end='|')
                print(' DR = ',  element.DR,  'attempt =', element.attempts)

                if (element.attempts == 2): element.DR = 4
                if (element.attempts == 4): element.DR = 2

                try: # works only for LoRa, Sigfox generates error
                    element.socket.setsockopt(socket.SOL_LORA, socket.SO_DR, element.DR)
                    element.socket.setblocking(True)
                    element.socket.settimeout(10)
                except:
                    pass

                pycom.rgbled(0xFF0000) # LED sending
#
                try:
                    element.socket.send(bytes(element.comprimed))
                except:
                    print ("TIMEOUT in sending")

                element.attempts += 1

                pycom.rgbled(0x0000FF) # LED blue wait for ACK

                try:
                    data = element.socket.recv(64)
                    dataRcv = True
                    pycom.rgbled(0x00FF00) # LED green ACK received
                except:
                    print ('timeout in receive')
                    dataRcv = False
                    pycom.rgbled(0x000000)


                element.socket.setblocking(False)


                if (dataRcv):
                    print("receive DATA", data)

                    respRuleId = data[0:1]
                    respCompCoap = data [1:]

                    print ("RuleId =", respRuleId, "content ", respCompCoap)

                    decRule = self.dec.RuleMngt.FindRuleFromID(respRuleId[0])

                    if (decRule == None):
                        print("No Rule")
                    else:
                        resPkt = bytearray(b'')
                        CoAPResp = bytearray(b'')

                        respPkt, respPktLength = self.dec.apply(respCompCoap, decRule, "dw")
                        print ("decompressing ", respPkt, '/', respPktLength)

                        IPv6Header = respPkt [0:40]
                        UDPHeader  = respPkt [40:48]
                        CoAPresp = respPkt[48:]

                        ack = Message(CoAPresp)

                        print ("CoAP response = ", CoAPresp)

                    if (ack.type() == ACK):
                        self.acked(ack)

            else: # Queue empty
                print('Empty list')

            time.sleep(20)

        #end while

        lastTime = finishIn-time.time()
        print("no more time for retransmission:", lastTime)
        if (lastTime > 0): time.sleep (finishIn - time.time())

    def IP_UDP(self,  ips,  ipd,  ps,  pd,  ulp):

        self.IP_buffer = struct.pack ('!HHHBB', 0x6000, 0x0000, len(ulp)+8, 17, 30) +\
        ips +  \
        ipd + \
        struct.pack ("!HHHH", ps, pd, len(ulp)+8, 0x0000) + \
        ulp


        return self.IP_buffer

    def th_func(self,  delay, id):
        while True:
            time.sleep(delay)
            print('Running thread %d' % id)


class Message:

    """
    class CoAP for client and server
    """

    def __init__(self,  buf=b''):
        self.buffer = buf
        self.option = 0

    def __dump_buffer(self):
        for bytes in self.buffer:
            print (hex(bytes),end= '-')

    def new_header (self,  type=CON,  code=GET,  token = 0x12, midSize=16):

        global mid

        self.buffer = bytearray()

        # First 32 bit word
        byte = ((01) << 6) | (type <<4) | 0x01 # need to compute token length
# /!\ Token is one byte long, should be changed to allow different sizes
        self.buffer = struct.pack ('!BBHB', byte, code, mid, token)

# In some cases the Message ID size must be limited to a smaller number of bits
# To allow rule selection, especially with MSB the size must be controlled

        mid = (mid + 1) % (1 << midSize)
        if (mid == 0): mid = 1 # mid = 0 may be ack with a random number
        print("MID = ", mid)

    def __add_option_TL (self, T, L ):
        delta = T - self.option
        self.option = T

        if (delta < 13) and (L < 13) is True:
            self.buffer += struct.pack('B', (delta<<4) | L)
        else:
            print('Not Done')


    def add_option_path(self, path=''):
        self.__add_option_TL(11,  len(path))
        self.buffer += path

    def add_option_query(self, query=''):
        self.__add_option_TL(15,  len(query))
        self.buffer += query

    def end_option(self):
        self.buffer += struct.pack('B', 0xFF)

    def add_value(self,  m=''):
        print ('Type = ', type(m))

        if (type(m)) == type(str()):
            print ("we have a string")
            self.buffer == m
        elif (type(m) == CBOR):
            print('du CBOR')
            for char in m.buffer:
                self.buffer += struct.pack('B', char)

        self.__dump_buffer()

    def to_coap(self):
        return self.buffer

    def type (self):
        return((self.buffer[0] & 0x30) >> 4)

    def mid(self):
        return self.buffer[2] << 8 | self.buffer[3]
