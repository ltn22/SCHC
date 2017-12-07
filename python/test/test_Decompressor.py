from .. import Decompressor
from .. import BitBuffer
from .. import RuleMngt

def test___init__():
    dec = Decompressor.Decompressor(None)
    actionEntries = [
            "not-sent",
            "value-sent",
            "mapping-sent",
            "LSB",
            "compute-length",
            "compute-checksum",
    ]
    for a in actionEntries:
        assert(a in dec.DecompressionActions)

    fieldSizeEntries = [
            "IPv6.version",
            "IPv6.trafficClass",
            "IPv6.flowLabel",
            "IPv6.payloadLength",
            "IPv6.nextHeader",
            "IPv6.hopLimit",
            "IPv6.checksum",
            "IPv6.prefixES",
            "IPv6.iidES",
            "IPv6.prefixLA",
            "IPv6.iidLA",
            "UDP.PortES",
            "UDP.PortLA",
            "UDP.length",
            "UDP.checksum",
            "CoAP.version",
            "CoAP.type",
            "CoAP.tokenLength",
            "CoAP.code",
            "CoAP.messageID",
            "CoAP.token",
            "CoAP.Uri-Path",
            "CoAP.Content-Format",
            "CoAP.Uri-Query",
            "CoAP.Option-End",
    ]
    for f in fieldSizeEntries:
        assert(f in dec.field_size)

#def test_DA_notSent():
#    buf = BitBuffer.BitBuffer()
#    dec = Decompressor.Decompressor(None)
#    TV = 1
#    dec.DA_notSent(buf, [], TV, 4, 'fixed', '', '')
#    assert(len(buf._buf) == 0)

#Uncomment when 'buff' typo is fixed in implem
#def test_DA_valueSent_fixed():
#    buf = BitBuffer.BitBuffer()
#    dec = Decompressor.Decompressor(None)
#    headers = BitBuffer.BitBuffer('0101')
#    length = 4
#    dec.DA_valueSent(buf, headers, '', length, 'fixed', '', 'direct')
#
#    assert(buf._buf == headers._buf)


#Uncomment when 'opt_num' error is fixed (uninitialized)
#def test_DA_valueSent_variable():
#    buf = BitBuffer.BitBuffer()
#    dec = Decompressor.Decompressor(None)
#    headers = BitBuffer.BitBuffer('1101')
#    length = 8
#    dec.DA_valueSent(buf, headers, '', length, 'variable', '', {'CoAPOption':11})
#
#    assert(buf._buf == headers._buf)


#Review when bitbuffer fully tested
#def test_DA_mappingSent():
#    TV = [0, 2, 1]
#    buf = BitBuffer.BitBuffer()
#    headers = BitBuffer.BitBuffer(b'01')
#    dec = Decompressor.Decompressor(None)
#    dec.DA_mappingSent(buf, headers, TV, 2, "fixed", "", "")
#    assert(buf._buf == 2)

#Review when append thing in Decompressor is fixed
#def test_DA_LSB_fixed_str():
#    TV = b'1101'
#    buf = BitBuffer.BitBuffer()
#    headers = BitBuffer.BitBuffer(b'010101')
#    dec = Decompressor.Decompressor(None)
#    dec.DA_LSB(buf, headers, TV, 8, 'fixed', 4, '')
#    assert(buf._buf == '11010101')


#Review when bitbuffer fully tested
#def test_DA_LSB_fixed_int():
#    TV = 12 # 1100
#    buf = BitBuffer.BitBuffer()
#    headers = BitBuffer.BitBuffer(b'0101')
#    dec = Decompressor.Decompressor(None)
#    dec.DA_LSB(buf, headers, TV, 8, 'fixed', 4, '')
#    assert(str(buf._buf) == '11000101')

def test_DA_computeLength():
    buf = BitBuffer.BitBuffer()
    headers = BitBuffer.BitBuffer(b'12')
    dec = Decompressor.Decompressor(None)
    dec.DA_computeLength(buf, headers, '', '', '', '', '' )
    assert(buf._buf == bytearray(b'\xFF\xFF'))

def test_DA_computeChecksum():
    buf = BitBuffer.BitBuffer()
    headers = BitBuffer.BitBuffer(b'12')
    dec = Decompressor.Decompressor(None)
    dec.DA_computeChecksum(buf, headers, '', '', '', '', '' )
    assert(buf._buf == bytearray(b'\xCC\xCC'))

# This is just for example, the assertion should be done compared to a bytearray build from compressor information
def test_apply ():
    rule_coap1 = {"ruleid"  : 1,
              "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
                           ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
                           ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
                           ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                           ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
                           ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
                           ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                           ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
                           ["IPv6.prefixLA",     1,  "bi", [0x2001066073010001,
                                                            0x2001123456789012,
                                                            0x2001123456789013,
                                                            0xFE80000000000000],"match-mapping", "mapping-sent"],
                           ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
                           ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
                           ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
                           ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                           ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                           ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                           ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
                           ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
                           ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                           ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
                           ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                           ["CoAP.messageID",    1,  "bi", 1,                  "MSB(12)", "LSB"],
                           ["CoAP.token",        1,  "bi", 0x80,               "MSB(4)", "LSB"],
                           ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
                           ["CoAP.Uri-Path",     2,  "up", "bar",              "equal", "not-sent"],
                           ["CoAP.Uri-Path",     3,  "up", None,               "ignore", "value-sent"],
                           ["CoAP.Uri-Query",    1,  "up", "k=",               "MSB(16)", "LSB"],
                           ["CoAP.Option-End",   1,  "up", 0xFF,               "equal", "not-sent"]
                        ]}
    compressed = bytearray(b'\xde\x40') # 11 bits
    RM = RuleMngt.RuleManager()
    RM.addRule(rule_coap1)
    rule = RM.FindRuleFromID(1)
    dec = Decompressor.Decompressor(RM)

    header, length = dec.apply (compressed, rule, "dw")
    assert(header == bytearray(b'`\x00\x00\x00\xff\xff\x11\x1e\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\xff\xff\xcc\xccaE\x00\x0f\x82'))
