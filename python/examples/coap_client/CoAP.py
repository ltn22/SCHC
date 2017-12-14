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

mid = 1

class Message:

    """
    class CoAP for client and server
    """

    def __init__( self, buf = b'' ):
        """ Coap message constructor """
        self.buffer = buf
        self.option = 0

    def __dump_buffer( self ):
        """Dumps the content of the message as hexa"""
        for bytes in self.buffer:
            print ( hex( bytes ), end = '-' )

    def new_header ( self, type = CON, code = GET, token = 0x12, midSize = 16 ):
        "Creates a new message header"

        global mid

        self.buffer = bytearray()

        # First 32 bit word
        byte = ( ( 1 ) << 6 ) | ( type << 4 ) | 0x01  # need to compute token length
# /!\ Token is one byte long, should be changed to allow different sizes
        self.buffer = struct.pack ( '!BBHB', byte, code, mid, token )

# In some cases the Message ID size must be limited to a smaller number of bits
# To allow rule selection, especially with MSB the size must be controlled

        mid = ( mid + 1 ) % ( 1 << midSize )
        if ( mid == 0 ): mid = 1  # mid = 0 may be ack with a random number
        print( "MID = ", mid )

    def __add_option_TL ( self, T, L ):
        """  adds an option at a specific length """
        delta = T - self.option
        self.option = T

        if ( delta < 13 ) and ( L < 13 ) is True:
            self.buffer += struct.pack( 'B', ( delta << 4 ) | L )
        else:
            print( 'Not Done' )


    def add_option_path( self, path = '' ):
        "Adds a path element to the message"
        self.__add_option_TL( 11, len( path ) )
        self.buffer += path

    def add_option_query( self, query = '' ):
        "Adds a CoAP query to the message"
        self.__add_option_TL( 15, len( query ) )
        self.buffer += query

    def end_option( self ):
        "Marks the end of the coap option list"
        self.buffer += struct.pack( 'B', 0xFF )

    def add_value( self, pvalue = '' ):
        '''Adds a value to the message'''
        print ( 'Type = ', type( pvalue ) )

        if isinstance(pvalue, str):
            self.buffer = pvalue

        self.__dump_buffer()

    def to_coap( self ):
        """ Returns the message's buffer"""
        return self.buffer

    def type ( self ):
        """Returns the message's CoAP type"""
        return( ( self.buffer[0] & 0x30 ) >> 4 )
