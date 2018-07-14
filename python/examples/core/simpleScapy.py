from scapy.all import *
import scapy.contrib.coap

IPv6Header = IPv6(
    version = 6,
    tc      = 0,
    fl      = 0,
    hlim    = 30,
#    src     = "2001:470:1f12:9f2::22",
    dst     = "2001:41d0:401:3100::57d7"
    )

sendp(IPv6Header/ ICMPv6EchoRequest(data='A'*5), iface="he-ipv6")