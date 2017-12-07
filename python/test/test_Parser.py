from SCHC import Parser

def test___init__():
    parser = Parser.Parser()
    assert(len(parser.payload) == 0)
    assert(len(parser.header_fields) == 0)

def test_dump(capsys):
    parser = Parser.Parser()
    optionName = "optName"
    fieldPos = 1
    optionValue = "optval"
    parser.header_fields = {(optionName, fieldPos):optionValue}
    parser.dump()
    out, err = capsys.readouterr()
    assert(optionName in out)
    assert(str(fieldPos) in out)
    assert(optionValue in out)

def test_parser():
    ipv6 =  bytearray(b'`\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3foo\x03bar\x06ABCD==Fk=eth0\xff\x84\x01\x82  &Ehello')
    parser = Parser.Parser()
    headers, payload = parser.parser(ipv6)

    assert(payload ==  b'\x84\x01\x82  &Ehello')
