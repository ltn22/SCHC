'''Bit buffer provides a way to write bits in a buffer and obtain the resulting byte array'''

class BitBuffer(object):
    '''Bit buffer'''

    def __init__(self, default_buf=b''):
        self._buf = bytearray(default_buf)
        self._bit_index = 0

    def add_bit(self, bit):
        byte_index = (self._bit_index >> 3)
        offset = 7 - (self._bit_index & 7)

        if len(self._buf) < (byte_index + 1):
            self._buf.append(0)

        if bit != 0:
            self._buf[byte_index] |= (1 << offset)

        self._bit_index += 1

    def next_bit(self):
        byte_index = (self._bit_index >> 3)
        offset = 7 - (self._bit_index & 7)

        msk = 1 << offset
        bit = self._buf[byte_index] & msk

        self._bit_index += 1

        if bit != 0:
            return 0x01
        else:
            return 0x00

    def add_byte(self, byte):
        for i in range(7, -1, -1):
            self.add_bit(byte & (1 << i))

    def add_bytes(self, buf):
        for byte in buf:
            self.add_byte(byte)

    def buffer(self):
        return self._buf

    def size(self):
        return self._bit_index
