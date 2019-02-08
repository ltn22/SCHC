# pylint: disable=import-error
# Module paths fixed at upload by Makefile
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

    This file presents four rules for the SCHC RuleManager used in sensor.py
    each of them acts differently on the packet's layers, compressing either
        - No layers
        - The IPv6 layer only
        - The IPv6 and UDP layers
        - All layers

        
'''
import CoAP

RULE_NO_COMPRESSION = { \
            "ruleid"  : 0,
            "content" : [["IPv6.version", 1, "bi", 6, "ignore", "value-sent"],
                         ["IPv6.trafficClass", 1, "bi", 0x00, "ignore", "value-sent"],
                         ["IPv6.flowLabel", 1, "bi", 0x000000, "ignore", "value-sent"],
                         ["IPv6.payloadLength", 1, "bi", None, "ignore", "value-sent"],
                         ["IPv6.nextHeader", 1, "bi", 17, "ignore", "value-sent"],
                         ["IPv6.hopLimit", 1, "bi", 30, "ignore", "value-sent"],
                         ["IPv6.prefixES", 1, "bi", 0xFE80000000000000, "ignore", "value-sent"],
                         ["IPv6.iidES", 1, "bi", 0x0000000000000001, "ignore", "value-sent"],
                         ["IPv6.prefixLA", 1, "bi", 0xFE80000000000000, "ignore", "value-sent"],
                         ["IPv6.iidLA", 1, "bi", 0x0000000000000002, "ignore", "value-sent"],
                         ["UDP.PortES", 1, "bi", 5682, "ignore", "value-sent"],
                         ["UDP.PortLA", 1, "bi", 5683, "ignore", "value-sent"],
                         ["UDP.length", 1, "bi", None, "ignore", "value-sent"],
                         ["UDP.checksum", 1, "bi", None, "ignore", "value-sent"],
                         ["CoAP.version", 1, "bi", 1, "ignore", "value-sent"],
                         ["CoAP.type", 1, "up", CoAP.CON, "ignore", "value-sent"],
                         ["CoAP.type", 1, "dw", 2, "ignore", "value-sent"],
                         ["CoAP.tokenLength", 1, "bi", 1, "ignore", "value-sent"],
                         ["CoAP.code", 1, "up", 2, "ignore", "value-sent"],
                         ["CoAP.code", 1, "dw", [69, 132], "ignore", "value-sent"],
                         ["CoAP.messageID", 1, "bi", 0, "ignore", "value-sent"],
                         ["CoAP.token", 1, "bi", 0x80, "ignore", "value-sent"],
                         ["CoAP.Uri-Path", 1, "up", "foo", "ignore", "value-sent"],
                         ["CoAP.Uri-Path", 2, "up", "bar", "ignore", "value-sent"],
                         ["CoAP.Option-End", 1, "up", 0xFF, "equal", "not-sent"]
                        ]}
RULE_COMPRESS_IPV6 = {\
             "ruleid"  : 1,
             "content" : [["IPv6.version", 1, "bi", 6, "equal", "not-sent"],
                          ["IPv6.trafficClass", 1, "bi", 0x00, "equal", "not-sent"],
                          ["IPv6.flowLabel", 1, "bi", 0x000000, "equal", "not-sent"],
                          ["IPv6.payloadLength", 1, "bi", None, "ignore", "compute-length"],
                          ["IPv6.nextHeader", 1, "bi", 17, "equal", "not-sent"],
                          ["IPv6.hopLimit", 1, "bi", 30, "ignore", "not-sent"],
                          ["IPv6.prefixES", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES", 1, "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA", 1, "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES", 1, "bi", 5682, "ignore", "value-sent"],
                          ["UDP.PortLA", 1, "bi", 5683, "ignore", "value-sent"],
                          ["UDP.length", 1, "bi", None, "ignore", "value-sent"],
                          ["UDP.checksum", 1, "bi", None, "ignore", "value-sent"],
                          ["CoAP.version", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.type", 1, "bi", 0, "ignore", "value-sent"],
                          ["CoAP.tokenLength", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.code", 1, "bi", 2, "ignore", "value-sent"],
                          ["CoAP.messageID", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.token", 1, "bi", 0x01, "ignore", "value-sent"],
                          ["CoAP.Uri-Path", 1, "up", "foo", "ignore", "value-sent"],
                          ["CoAP.Uri-Path", 2, "up", "bar", "ignore", "value-sent"],
                          ["CoAP.Option-End", 1, "up", 0xFF, "equal", "not-sent"]
                         ]
                     }
RULE_COMPRESS_IPV6_UDP = {\
             "ruleid"  : 2,
             "content" : [["IPv6.version", 1, "bi", 6, "equal", "not-sent"],
                          ["IPv6.trafficClass", 1, "bi", 0x00, "equal", "not-sent"],
                          ["IPv6.flowLabel", 1, "bi", 0x000000, "equal", "not-sent"],
                          ["IPv6.payloadLength", 1, "bi", None, "ignore", "compute-length"],
                          ["IPv6.nextHeader", 1, "bi", 17, "equal", "not-sent"],
                          ["IPv6.hopLimit", 1, "bi", 30, "ignore", "not-sent"],
                          ["IPv6.prefixES", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES", 1, "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA", 1, "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES", 1, "bi", 5682, "equal", "not-sent"],
                          ["UDP.PortLA", 1, "bi", 5555, "equal", "not-sent"],
                          ["UDP.length", 1, "bi", None, "ignore", "compute-length"],
                          ["UDP.checksum", 1, "bi", None, "ignore", "compute-checksum"],
                          ["CoAP.version", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.type", 1, "bi", 0, "ignore", "value-sent"],
                          ["CoAP.tokenLength", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.code", 1, "bi", 2, "ignore", "value-sent"],
                          ["CoAP.messageID", 1, "bi", 1, "ignore", "value-sent"],
                          ["CoAP.token", 1, "bi", 0x01, "ignore", "value-sent"],
                          ["CoAP.Uri-Path", 1, "up", "foo", "ignore", "value-sent"],
                          ["CoAP.Uri-Path", 2, "up", "bar", "ignore", "value-sent"],
                          ["CoAP.Option-End", 1, "up", 0xFF, "equal", "not-sent"]
                         ]
                         }
RULE_COMPRESS_ALL = {\
             "ruleid"  : 3,
             "content" : [["IPv6.version", 1, "bi", 6, "equal", "not-sent"],
                          ["IPv6.trafficClass", 1, "bi", 0x00, "equal", "not-sent"],
                          ["IPv6.flowLabel", 1, "bi", 0x000000, "equal", "not-sent"],
                          ["IPv6.payloadLength", 1, "bi", None, "ignore", "compute-length"],
                          ["IPv6.nextHeader", 1, "bi", 17, "equal", "not-sent"],
                          ["IPv6.hopLimit", 1, "bi", 30, "ignore", "not-sent"],
                          ["IPv6.prefixES", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES", 1, "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA", 1, "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA", 1, "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES", 1, "bi", 5682, "equal", "not-sent"],
                          ["UDP.PortLA", 1, "bi", 5555, "equal", "not-sent"],
                          ["UDP.length", 1, "bi", None, "ignore", "compute-length"],
                          ["UDP.checksum", 1, "bi", None, "ignore", "compute-checksum"],
                          ["CoAP.version", 1, "bi", 1, "equal", "not-sent"],
                          ["CoAP.type", 1, "bi", 0, "equal", "not-sent"],
                          ["CoAP.tokenLength", 1, "bi", 1, "equal", "not-sent"],
                          ["CoAP.code", 1, "bi", 2, "equal", "not-sent"],
                          ["CoAP.messageID", 1, "bi", 1, "MSB(4)", "LSB"],
                          ["CoAP.token", 1, "bi", 0x82, "equal", "not-sent"],
                          ["CoAP.Uri-Path", 1, "up", "foo", "equal", "not-sent"],
                          ["CoAP.Uri-Path", 2, "up", "bar", "ignore", "value-sent"],
                          ["CoAP.Option-End", 1, "up", 0xFF, "equal", "not-sent"]
                         ]
                    }
RULE_COMPRESS_COAP = {\
             "ruleid"  : 28,
             "content" :[["CoAP.version", 1, "bi", 1, "equal", "not-sent"],
                         ["CoAP.type", 1, "bi", 1, "equal", "not-sent"],
                         ["CoAP.tokenLength", 1, "bi", 1, "equal", "not-sent"],
                         ["CoAP.code", 1, "bi", 2, "equal", "not-sent"],
                         ["CoAP.messageID", 1, "bi", 1, "MSB(4)", "LSB"],
                         ["CoAP.token", 1, "bi", 0x82, "equal", "not-sent"],
                         ["CoAP.Uri-Path", 1, "up", "temperature", "equal", "not-sent"],
                         ["CoAP.Option-End", 1, "up", 0xFF, "equal", "not-sent"]
                        ]
                    }

