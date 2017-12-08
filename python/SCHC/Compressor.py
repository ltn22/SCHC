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
from re import search
from SCHC import BitBuffer

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
                reg = search( r'\((.*)\)', CA )
                if reg:
                    # group(1) returns the first parenthesized subgroup
                    arg = int( reg.group( 1 ) )
                    CA = CA.split( '(' )[0]  # remove the argument and parentheses
                    CA = CA.replace ( ' ', '' )  # suppress blank if any
                else:  # no length specified, based it on MO
                    MO = entry[4]
                    reg = search( r'\((.*)\)', MO )
                    if reg:
                        arg = int( reg.group( 1 ) )
                        arg = fieldLength - arg

# CA must be cleaned of argument MSB(4) => MSB and arg = 4
                # print ('Call {0:10s} TV = '.format(CA), TV, ' FV = ', FV)
                self.CompressionActions[CA]( buf, TV, FV, fieldLength, fixvar, arg )

        return buf
