from .. import Compressor
from .. import BitBuffer

def test___init__():
    comp = Compressor.Compressor(None)

    assert(len(comp.context) == 0)
    assert( "not-sent" in comp.CompressionActions)
    assert( "value-sent" in comp.CompressionActions)
    assert( "mapping-sent" in comp.CompressionActions)
    assert( "LSB" in comp.CompressionActions)
    assert( "compute-length" in comp.CompressionActions)
    assert( "compute-checksum" in comp.CompressionActions)


def test_CA_notSent():
    comp = Compressor.Compressor(None)
    assert(comp.CA_notSent('', '', '', 0, 0, 0) == None)

# No length taken into account ?
#def test_CA_valueSent_str():
#    comp = Compressor.Compressor(None)
#    value = '01001'
#    buf = BitBuffer.BitBuffer()
#    comp.CA_valueSent(buf, '', value, 0, 0, 0)
#    assert(buf._buf == value)

#def test_CA_valueSent_int():
#    comp = Compressor.Compressor(None)
#    buf = BitBuffer.BitBuffer()
#    value = int('1001101', 2)
#    comp.CA_valueSent(buf, b'', value, 4*16, 0, 0)
#    assert(buf._buf == value)

#def test_CA_mappingSent():
#    comp = Compressor.Compressor(None)
#    TV = [1, 2, 34]
#    FV = 2
#    buf = BitBuffer.BitBuffer()
#    comp.CA_mappingSent(buf, TV, FV, 0, 0, 0)

def test_CA_LSB():
    assert(True)
def test_apply ():
    assert(True)
