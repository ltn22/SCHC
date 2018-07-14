import os
import sys
sys.path.insert(0, '../..')

import getopt
import base64
import pprint
import json
import binascii

from SCHC.RuleMngt import RuleManager
from SCHC.Parser import Parser
from SCHC.Compressor import Compressor
from SCHC.Decompressor import Decompressor

import SCHC_RULES

RM = RuleManager()
RM.addRule(SCHC_RULES.rule_coap0)
RM.addRule(SCHC_RULES.rule_coap1)
RM.addRule(SCHC_RULES.rule_coap2)

decompressor = Decompressor (RM)
packetParser = Parser()

payload = binascii.unhexlify('0215043213243400030e9c')

ruleId = payload[0:1]
residue = payload[1:]

print ("ruleId = ", ruleId, ruleId[0], "residue =", residue)

decRule = RM.FindRuleFromID(ruleId[0])

print (decRule)

if decRule:
    header = bytearray(b'')
    data = bytearray(b'')

    header, data = decompressor.apply(residue, decRule, "up")

    print (binascii.hexlify(header))