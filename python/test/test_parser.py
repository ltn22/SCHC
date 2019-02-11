""" Tests SCHC's Parser module"""
from SCHC import Parser

def test___init__():
    """ Tests Parser's constructor"""
    parser = Parser.Parser()
    assert not parser.payload
    assert not parser.header_fields

def test_dump(capsys):
    """ Tests Parser's dump function"""
    parser = Parser.Parser()
    option_name = "optName"
    field_pos = 1
    option_value = "optval"
    parser.header_fields = {(option_name, field_pos):option_value}
    parser.dump()
    out, _ = capsys.readouterr()
    assert option_name in out
    assert str(field_pos) in out
    assert option_value in out

def test_parser():
    """ Tests Parser's parser function """
    ipv6 = bytearray(b"""`\
\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x02\x16\
2\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3\
foo\x03bar\x06ABCD==Fk=eth0\xff\x84\x01\
\x82  &Ehello""")
    parser = Parser.Parser()
    _, payload = parser.parser(ipv6,"")

    assert payload == b'\x84\x01\x82  &Ehello'
