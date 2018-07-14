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

import struct
import re
from SCHC import BitBuffer

class Decompressor:

    def __init__( self, RM ):
        self.RuleMngt = RM

        self.DecompressionActions = {
            "not-sent" : self.DA_notSent,
            "value-sent" : self.DA_valueSent,
            "mapping-sent" : self.DA_mappingSent,
            "LSB": self.DA_LSB,
            "compute-length" : self.DA_computeLength,
            "compute-checksum" : self.DA_computeChecksum
        }

        self.field_size = {
            "IPv6.version": [4, "direct"],
            "IPv6.trafficClass": [8, "direct"],
            "IPv6.flowLabel": [20, "direct"],
            "IPv6.payloadLength": [16, "direct"],
            "IPv6.nextHeader": [8, "direct"],
            "IPv6.hopLimit": [8, "direct"],
            "IPv6.checksum": [16, "direct"],
            "IPv6.prefixES": [64, "direct"],
            "IPv6.iidES": [64, "direct"],
            "IPv6.prefixLA": [64, "direct"],
            "IPv6.iidLA": [64, "direct"],
            "UDP.PortES": [16, "direct"],
            "UDP.PortLA": [16, "direct"],
            "UDP.length": [16, "direct"],
            "UDP.checksum": [16, "direct"],
            "CoAP.version": [2, "direct"],
            "CoAP.type": [2, "direct"],
            "CoAP.tokenLength": [4, "direct"],
            "CoAP.code": [8, "direct"],
            "CoAP.messageID": [16, "direct"],
            "CoAP.token": [8, "direct"],  # MUST be set to TKL value
            "CoAP.Location-Path" :["variable", {"CoAPOption": 8}],
            "CoAP.Uri-Path" :  ["variable", {"CoAPOption": 11}],
            "CoAP.Content-Format" : ["variable", {"CoAPOption": 12}],
            "CoAP.Uri-Query" : ["variable", {"CoAPOption": 15}],
            "CoAP.Option-End" : [8, "direct"]
        }

    def compute_CoAPOption (self, buf,  optType, length, value ):
        print( "Not implemented" )
        print ("current type = ", self.opt_num, "type =", optType, "length = ", length, "value =", value)

        deltaT = optType - self.opt_num
        self.opt_num = optType

        lengthByte = length // 8
        print ("lengthByte = ", lengthByte)

        if (deltaT > 14) or (lengthByte > 14):
            print ("Not implemented Type or Length too big")
            return

        firstByte = (deltaT << 4) | lengthByte
        print ("first Byte =", hex(firstByte))
        buf.add_byte (firstByte)
        
        buf.add_bytes(bytes(value, encoding='utf-8'))
        
        return

    def DA_notSent( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_notSent", TV, length, nature, arg, "algoo=", algo )

        if ( nature == "variable" ):
            print ("TV=", TV, len(TV))
            length = len( TV ) * 8

        
        if ( type( TV ) is int ):
            for i in range ( length - 1, -1, -1 ):
                buf.add_bit( TV & ( 1 << i ) )
        elif type (TV) is str:
            if algo == "direct":
                print ("Direct not implemented")
                
            elif "CoAPOption" in algo:
                print ("CoAP Option")
                self.compute_CoAPOption (buf, algo["CoAPOption"], length, TV)
            else:
                print ("algo", algo, "Not implemented")
                

    def DA_valueSent( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_notSent", TV, length, nature, arg, algo )
        if ( nature == "variable" ):
            leng = 0
            for i in range ( 0, 4 ):
                leng <<= 1
                leng |= headers.next_bit()

            leng *= 8

            if ( algo == "direct" ):
                self.DA_valueSent( buf, headers, null, leng, "fixed", null, algo )
            else:
                if "CoAPOption" in algo:
                    delta = algo["CoAPOption"] - self.opt_num
                    if leng != 0:
                        # buff = bytearray ( b'' )
                        buff = []
                        for b in range( 0, leng ):  # This is not well done
                            octet = b // 8
                            offset = b % 8
                            if len( buff ) == octet: 
                                buff.append( 0x00 )
                                  
                            buff[octet] = buff[octet] << 1 | headers.next_bit()
                            
                        delta_opt_len = algo["CoAPOption"] << 4 | int( leng / 8 )
                        # delta_opt_len = delta << 4 | len( buff )
                        buf.add_byte( delta_opt_len )
                        buf.add_bytes( buff )
                        buf._bit_index += 8 * len( buff )
                    else:
                        delta_opt_len = algo["CoAPOption"] << 4
                        buf.add_byte( delta_opt_len )
                        buf._bit_index += 8
                        # for i in range( 4 ):
                        #    buf.add_bit( 0 )
                        # Puede que falte agregar el TL - T.. - Length
                    
                    self.opt_num = algo["CoAPOption"]
                        
        elif nature == "fixed":
            if algo == "direct":
                for i in range( length ):
                    buf.add_bit( headers.next_bit() )

    def DA_mappingSent( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_mappingSent", TV, length, nature, arg, algo )

        elmNb = len( TV )
        bitNb = 0
        while ( ( 1 << bitNb ) < elmNb ): bitNb += 1

        index = 0
        for i in range( 0, bitNb ):
            v = headers.next_bit()
            index <<= 1
            index |= v

        self.DA_notSent( buf, headers, TV[index], length, "fixed", None, algo )


    def DA_LSB( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_LSB", TV, length, nature, arg, algo )
        if ( nature == "variable" ):
            leng = 0
            for i in range ( 0, 4 ):
                leng <<= 1
                leng |= headers.next_bit()

            leng *= 8
            self.DA_LSB( buf, headers, TV, leng, "fixed", None, algo )
        elif nature == "fixed":
            if type( TV ) is int:
                merged = TV

                for i in range( arg - 1, -1, -1 ):
                    binval = headers.next_bit()

                    merged |= binval << i

                    print ( "merged TV ", TV, " and binval ", binval, " = "   , merged )

                self.DA_notSent( buf, headers, merged, length, "fixed", None, algo )
            elif type( TV ) == str:
                if ( length % 8 != 0 ):
                    print ( "error" )
                else:
                    charNb = length // 8
                    for i in range( 0, charNb ):
                        value = 0
                        for k in range ( 7, -1, -1 ):
                            value |= headers.next_bit() << k
                        TV.append( value )
                    self.DA_notSent( buf, headers, TV, len( TV ) * 8, "fixed", None, algo )
            else:
                print ( "not implemented" )

    def DA_computeLength( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_computeLength", TV, length, nature, arg, algo )
        self.DA_notSent( buf, headers, 0xFFFF, 16, "fixed", None, algo )

    def DA_computeChecksum( self, buf, headers, TV, length, nature, arg, algo ):
        print ( "DA_computeChecksum", TV, length, nature, arg, algo )
        self.DA_notSent( buf, headers, 0xCCCC, 16, "fixed", None, algo )

    def apply ( self, header, rule, direction ):
        buf = BitBuffer.BitBuffer()
        headersBuf = BitBuffer.BitBuffer( header )

        # print ('iBuf', self.iBuf, ' header ', header)
        for e in rule["content"]:
            FID = e[0]
            POS = e[1]
            DIR = e[2]

            if ( DIR == "bi" ) or ( DIR == direction ):
                TV = e[3]
                MO = e[4]
                DA = e[5]
                FV = None

                self.opt_num = 0

                nature = None
                arg = None
                reg = re.search( '\((.*)\)', DA )
                if reg:
                    # group(1) returns the first parenthesized subgroup
                    arg = int( reg.group( 1 ) )
                    DA = DA.split( '(' )[0]  # remove the argument and parentheses
                    DA = DA.replace ( ' ', '' )  # suppress blank if any
                else:  # no length specified, based it on MO
                    reg = re.search( '\((.*)\)', MO )
                    if reg:
                        arg = int( reg.group( 1 ) )

                if ( type( self.field_size[FID][0] ) is int ):
                    nature = "fixed"
                    size = self.field_size[FID][0]
                    if ( arg != None ):  # /!\ do not work is DA contains a value
                        arg = size - arg  # /!\ check if negative
                elif ( type ( self.field_size[FID][0] )is str ):
                    if ( self.field_size[FID][0] == "variable" ):
                        nature = "variable"
                    else:
                        print ( "/!\ Unknown field size keywork" )

                algo = self.field_size[FID][1]

                print ("DECOMPRESSION: ", "FID = ", FID, " DA = ", DA, " TV= ", TV, " size= ", size, " nature = ", nature, " arg = ", arg)

                self.DecompressionActions[DA]( buf, headersBuf, TV, size, nature, arg, algo )

        

        length = len( headersBuf.buffer() ) * 8 - headersBuf.size()
        if length != 0:
            
            # add payload marker
            
            if length % 8 != 0:
                length -= length % 8    
    
            for i in range( length ):
                buf.add_bit( headersBuf.next_bit() )

        return buf.buffer(), buf.size()

#                           fID                  Pos  DI  TV                  MO           CDA
# rule_coap0 = {"ruleid"  : 0,
#              "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
#                           ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
#                           ["IPv6.flowLabel",    1,  "bi", 0x000000,           "equal",  "not-sent"],
#                           ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
#                           ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
#                           ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
#                           ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
#                           ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
#                           ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
#                           ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
#                           ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
#                           ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
#                           ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
#                           ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
#                           ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
#                           ["CoAP.type",         1,  "bi", 0,                  "equal", "not-sent"],
#                           ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
#                           ["CoAP.code",         1,  "bi", 2,                  "equal", "not-sent"],
#                           ["CoAP.messageID",    1,  "bi", 1,                  "MSB(4)", "LSB"],
#                           ["CoAP.token",        1,  "bi", 0x01,               "MSB(4)", "LSB"],
#                           ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
#                           ["CoAP.Uri-Path",     2,  "up", "bar",              "ignore", "value-sent"],
#                        ]}
#
# rule_coap1 = {"ruleid"  : 1,
#              "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
#                           ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
#                           ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
#                           ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
#                           ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
#                           ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
#                           ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
#                           ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
#                           ["IPv6.prefixLA",     1,  "bi", [0x2001066073010001,
#                                                            0x2001123456789012,
#                                                            0x2001123456789013,
#                                                            0xFE80000000000000],"match-mapping", "mapping-sent"],
#                           ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
#                           ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
#                           ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
#                           ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
#                           ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
#                           ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
#                           ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
#                           ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
#                           ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
#                           ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
#                           ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
#                           ["CoAP.messageID",    1,  "bi", 1,                  "MSB(12)", "LSB"],
#                           ["CoAP.token",        1,  "bi", 0x80,               "MSB(4)", "LSB"],
#                           ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
#                           ["CoAP.Uri-Path",     2,  "up", "bar",              "equal", "not-sent"],
#                           ["CoAP.Uri-Path",     3,  "up", None,               "ignore", "value-sent"],
#                           ["CoAP.Uri-Query",    1,  "up", "k=",               "MSB(16)", "LSB"],
#                           ["CoAP.Option-End",   1,  "up", 0xFF,               "equal", "not-sent"]
#                        ]}
#
# compressed = bytearray(b'\xde\x40') # 11 bits
# RM = RuleManager()
# RM.addRule(rule_coap0)
# RM.addRule(rule_coap1)
#
# rule = RM.FindRuleFromID(1)
#
# dec = Decompressor(RM)
#
# header, length = dec.apply (compressed, rule, "dw")
# print (header, ' ', length, ' ', length/8)
