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



from binascii import hexlify, unhexlify
from struct import pack, unpack

option_names = {
    1: "CoAP.If-Match",
    3: "CoAP.Uri-Host",
    4: "CoAP.ETag",
    5: "CoAP.If-None-Match",
    6: "CoAP.Observe",
    7: "CoAP.Uri-Port",
    8: "CoAP.Location-Path",
    11: "CoAP.Uri-Path",
    12: "CoAP.Content-Format",
    14: "CoAP.Max-Age",
    15: "CoAP.Uri-Query",
    17: "CoAP.Accept",
    20: "CoAP.Location-Query",
    23: "CoAP.Block2",
    27: "CoAP.Block1",
    28: "CoAP.Size2",
    35: "CoAP.Proxy-Uri",
    39: "CoAP.Proxy-Scheme",
    60: "CoAP.Sizel",
    258: "CoAP.No-Response"
}


class Parser:

    def __init__(self):
        self.header_fields = {}
        self.payload = b""

    def dump(self):
        for e, v in self.header_fields:
            print ("{0:20} {1:3} ".format(e, v), self.header_fields[e, v])

    def parser(self, packet, direction="up"):
#        self.sepacketHexaContent = packet
        field_position = {}
        # The complete trame content in printed
        print("\n\t\tTrame content (hexa): %s" % hexlify(packet))

        print ('argument type', type(packet))

        self.header_fields = {}
        
        # The "IP_version" field is pulled apart
        firstByte = unpack('!BBHHBBQQQQHHHHBBH', packet[:52])
        print(firstByte)
        self.header_fields["IPv6.version", 1]      = [firstByte[0] >> 4, 4, 'fixed']
        self.header_fields["IPv6.trafficClass", 1] = [(firstByte[0] & 0x0F) << 4 | (firstByte[1] & 0xF0) >> 4, 8, 'fixed']
        self.header_fields["IPv6.flowLabel", 1]    = [(firstByte[1] & 0x0F ) << 16 | firstByte[2], 20, 'fixed']
        self.header_fields["IPv6.payloadLength", 1]= [firstByte[3], 16, 'fixed']
        self.header_fields["IPv6.nextHeader", 1]   = [firstByte[4], 8, 'fixed']
        self.header_fields["IPv6.hopLimit", 1]     = [firstByte[5], 8, 'fixed']

        if direction == "up":
            self.header_fields["IPv6.prefixES", 1]     = [firstByte[6], 64, 'fixed']
            self.header_fields["IPv6.iidES", 1]        = [firstByte[7], 64, 'fixed']
            self.header_fields["IPv6.prefixLA", 1]     = [firstByte[8], 64, 'fixed']
            self.header_fields["IPv6.iidLA", 1]        = [firstByte[9], 64, 'fixed']
        elif direction == "dw":
            self.header_fields["IPv6.prefixLA", 1]     = [firstByte[6], 64, 'fixed']
            self.header_fields["IPv6.iidLA", 1]        = [firstByte[7], 64, 'fixed']
            self.header_fields["IPv6.prefixES", 1]     = [firstByte[8], 64, 'fixed']
            self.header_fields["IPv6.iidES", 1]        = [firstByte[9], 64, 'fixed']
        else:
            raise ValueError ("unknwon direction")

        if firstByte[4] != 17:
            raise ValueError("IPv6 Proto unknown")

        if direction == "up":
            self.header_fields["UDP.PortES", 1]      = [firstByte[10], 16, 'fixed']
            self.header_fields["UDP.PortLA", 1]      = [firstByte[11], 16, 'fixed']
        elif direction == "dw":
            self.header_fields["UDP.PortLA", 1]      = [firstByte[10], 16, 'fixed']
            self.header_fields["UDP.PortES", 1]      = [firstByte[11], 16, 'fixed']
        else:
                raise ValueError("Unknown direction")
        
        self.header_fields["UDP.length", 1]      = [firstByte[12], 16, 'fixed']
        self.header_fields["UDP.checksum", 1]    = [firstByte[13], 16, 'fixed']
        self.header_fields["CoAP.version", 1]    = [firstByte[14] >> 6, 2, 'fixed']
        self.header_fields["CoAP.type", 1]       = [(firstByte[14] & 0x30) >> 4, 2, 'fixed']
        self.header_fields["CoAP.tokenLength", 1]= [firstByte[14] & 0x0F, 4, 'fixed']
        self.header_fields["CoAP.code", 1]       = [firstByte[15], 8, 'fixed']
        self.header_fields["CoAP.messageID", 1]  = [firstByte[16], 16, 'fixed']
        pos = 52 # next byte in packet

        token = int(0)
        for i in range(0, self.header_fields["CoAP.tokenLength", 1][0]):
            token <<= 8
            token += int(packet[pos+i])
            pos += 1
        self.header_fields["CoAP.token", 1] = [token, self.header_fields["CoAP.tokenLength", 1][0]*8, 'fixed']

        option_number = 0
        while (pos < len(packet)):
            print (">>>>", self.header_fields)
            if (int(packet[pos]) == 0xFF): break

            deltaTL = int(packet[pos])
            pos += 1
            deltaT = (deltaTL & 0xF0) >> 4
            # /!\ add long value
            option_number += int(deltaT)

            L = int(deltaTL & 0x0F)
            # /!\ add long values

            try:
                field_position[option_number] += 1
            except:
                field_position[option_number] = 1

            option_value = ''

            for i in range (0, L):
                option_value += chr(packet[pos])
                pos += 1
                # /!\ check if max length is reached
                
            try:
                self.header_fields[option_names[option_number], field_position[option_number]] = [option_value, L*8,  "variable"]
            except:
                raise ValueError("CoAP Option {} not found".format(option_number))

# now the data

        if(pos < len(packet)):
            if (int(packet[pos]) == 0xFF):
                self.header_fields["CoAP.Option-End", 1] = [0xFF, 8, 'fixed']
                pos += 1

                # while (pos < len(packet)):
                #     print (hex(packet[pos]), end='')
                #     pos += 1
                # print()

                return self.header_fields, packet[pos:]
            else:
                raise ValueError("error in CoAP option parsing")

        return self.header_fields, None
