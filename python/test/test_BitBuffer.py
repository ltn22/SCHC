from SCHC import BitBuffer

def test___init__():
    buf = BitBuffer.BitBuffer()
    assert (len(buf._buf) == 0)
    assert (buf._bit_index == 0)

def test___init__with_value():
    bitValue = b'1011'
    buf = BitBuffer.BitBuffer(bitValue)
    assert(len(buf._buf) == len(bitValue))
    assert(buf._bit_index == 0)

#def test_add_bit():
#    buf = BitBuffer.BitBuffer()
#    assert(buf._buf == bytearray(b''))
#    buf.add_bit(0)#
#    assert(buf._buf == bytearray(b'0'))

#def test_next_bit():
#    buf = BitBuffer.BitBuffer(b'01')
#    b = buf.next_bit()
#    assert(b == 0)
#    b = buf.next_bit()
#    assert(b == 1)
#    b = buf.next_bit()
#    assert(b == 0)

#def test_add_byte():
#    buf = BitBuffer.BitBuffer(b'01010000')
#    byte = 0x1
#    buf.add_byte(byte)
#    print buf._buf
#    assert (False)

#def test_add_bytes():
#    buf = BitBuffer.BitBuffer(b'01')
#    assert (True)

def test_buffer():
    buf = BitBuffer.BitBuffer(b'01')
    assert (buf.buffer() == b'01')

#def test_size():
#    buf = BitBuffer.BitBuffer(b'01')
#    assert (buf.size() == 2)
