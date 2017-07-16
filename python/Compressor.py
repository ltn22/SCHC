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

from Parser import Parser
import struct
from re import search
from RuleMngt import RuleManager
import binascii
import BitBuffer

class Compressor:

    def __init__( self, RM ):
        self.RuleMngt = RM

        self.context = []

        self.CompressionActions = {
            "not-sent" : self.CA_notSent,
            "value-sent" : self.CA_valueSent,
            "mapping-sent" : self.CA_mappingSent,
            "LSB": self.CA_LSB,
            "compute-length" : self.CA_notSent,
            "compute-checksum" : self.CA_notSent
        }

    def CA_notSent( self, buf, TV, FV, length, nature, arg ):
        return

    def CA_valueSent( self, buf, TV, FV, length, nature, arg ):
        print( '\tvalue-sent ', FV, ' ', length, ' ', arg )

        if ( nature == "variable" ):

            byteLength = int( length / 8 )  # based on CoAP option the unit is Bytes

            if ( byteLength > 15 ):
                print( "not yet impemented" )
                # /!\ 0xF indicate a longer length, then add the length on 1 byte
                return

            for pos in range ( 3, -1, -1 ):
                buf.add_bit( byteLength & ( 1 << pos ) )

            # print("Variable ", byteLength)

        if type( FV ) is int:
            FVbitmap = struct.pack( "!L", FV )

            octet = int( 4 - length / 8 )  # may not start from the begin of TVbitmap
            offset = int( length % 8 )  # not a full byte
            if offset == 0:
                offset = 7
            else:
                offset -= 1

            for pos in range ( octet, 4 ):
                for bitPos in range ( offset, -1, -1 ):
                    msk = ( 1 << bitPos )
                    buf.add_bit( FVbitmap[pos] & msk )
                    offset = 7

        elif type( FV ) is str:
            FVbitmap = bytearray( FV )
            for i in range ( 0, len( FVbitmap ) ):
                for bitPos in range ( 7, -1, -1 ):
                    msk = ( 1 << bitPos )
                    buf.add_bit( FVbitmap[i] & msk )

        else:
            print( 'bad type' )
            return

    def CA_mappingSent( self, buf, TV, FV, length, nature, arg ):
        # print( "\tCA match-mapping", type(TV))
        if type( TV ) is dict:
            print ( 'not implemented' )
            return False
        elif type( TV ) is list:
            elmNb = len ( TV )

            if ( elmNb > 255 ):
                print ( "list too big" )
                return

            bitNb = 0
            while ( ( 1 << bitNb ) < elmNb ) : bitNb += 1

            # print ("we need ", bitNb, " bit to send ", elmNb, ' values')

            idx = 0
            for mappingValue in TV:
                if type( mappingValue ) != type ( FV ):
                    return False
                if mappingValue == FV:
                    break
                idx += 1

            # print ('found elm ', idx)
            self.CA_valueSent ( buf, TV, idx, bitNb, "fixed", None )

        else:
            return False


    def CA_LSB( self, buf, TV, FV, length, nature, arg ):
        # print ('\tLSB', FV, 'length :', length, "nature ", nature, " arg ", arg)
        if type( FV ) is int:
            self.CA_valueSent ( buf, TV, FV, arg, nature, None )
        elif type( FV ) is str:
            octet = int( ( length - arg ) / 8 )
            self.CA_valueSent( buf, TV, FV[octet:], arg, nature, None )
        else:
            print( "not known" )
            return

    def apply ( self, headers, rule, direction ):
        buf = BitBuffer.BitBuffer()

        for entry in rule:
            FID = entry[0]
            POS = entry[1]
            #  print ("Field {0:20s} ".format(FID), end='> ')
            DI = entry [2]
            if ( DI == "bi" ) or ( DI == direction ):
                try:
                    FV = headers[FID, POS][0]
                except:
                    print( 'Field not found in rule' )
                    return None

                TV = entry[3]
                CA = entry[5]
                fieldLength = headers[FID, POS][1]
                fixvar = headers[FID, POS][2]  # nature of the field: fixed or variable

                # does the CDA has an argument
                arg = None
                reg = search( '\((.*)\)', CA )
                if reg:
                    # group(1) returns the first parenthesized subgroup
                    arg = int( reg.group( 1 ) )
                    CA = CA.split( '(' )[0]  # remove the argument and parentheses
                    CA = CA.replace ( ' ', '' )  # suppress blank if any
                else:  # no length specified, based it on MO
                    MO = entry[4]
                    reg = search( '\((.*)\)', MO )
                    if reg:
                        arg = int( reg.group( 1 ) )
                        # print ("MO arg = ", arg, "length = ", fieldLength)
                        arg = fieldLength - arg

# CA must be cleaned of argument MSB(4) => MSB and arg = 4
                # print ('Call {0:10s} TV = '.format(CA), TV, ' FV = ', FV)
                self.CompressionActions[CA]( buf, TV, FV, fieldLength, fixvar, arg )

        # print ("Compressor returns ", end='[]')
        # print(binascii.hexlify(self.eBuf), end=']')
        return buf


#
# #                           fID                  Pos  DI  TV                  MO           CDA
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
#
# ipv6 =  bytearray(b'`\x00\x00\x00\x00-\x11\x1e\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\x00-\x00\x00A\x02\x00\x01\x82\xb3foo\x03bar\x06ABCD==Fk=eth0\xff\x82\x19\x0bd\x1a\x00\x01\x8e\x96')
#
# p = Parser()
# f, data = p.parser(ipv6)
#
# RM = RuleManager()
# RM.addRule(rule_coap0)
# RM.addRule(rule_coap1)
#
# print("=====")
# print("F", f)
# print (len(f))
#
# print ("rule = ", RM.FindRuleFromHeader(f, "up"))
# print ("rule = ", RM.FindRuleFromID(1))
