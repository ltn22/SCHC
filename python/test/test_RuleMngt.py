import pytest
from .. import RuleMngt

def test_MO_ignore():
    assert (RuleMngt.MO_ignore("", "", 0))

def test_MO_equal():
    TV_0 = "value"
    FV_0 = "value"
    assert (RuleMngt.MO_equal(TV_0, FV_0, 0))
    TV_1 = "value"
    FV_1 = "value_2"
    assert (not RuleMngt.MO_equal(TV_1, FV_1, 0))
    TV_2 = "value"
    FV_2 = 5
    assert (not RuleMngt.MO_equal(TV_2, FV_2, 0))

def test_MO_matchmapping_list():
    TV_0 = [0, 1, 2, 3]
    FV_0 = 2
    assert (RuleMngt.MO_matchmapping(TV_0, FV_0, 0))

    TV_1 = ["0", "1", "2", "3"]
    FV_1 = 2
    assert (not RuleMngt.MO_matchmapping(TV_1, FV_1, 0))

    TV_2 = [0, 1, 2, 3]
    FV_2 = 4
    assert (not RuleMngt.MO_matchmapping(TV_2, FV_2, 0))

#def test_MO_matchmapping_dict():
#    TV_0 = {
#            "k1":1,
#            "k2":0,
#            "k3":4,
#            "k4":3,
#        }
#    FV_0 = 0
#    FV_1 = 5
#    assert (RuleMngt.MO_matchmapping(TV_0, FV_0, 0))
#    assert (not RuleMngt.MO_matchmapping(TV_0, FV_1, 0))

def test_MO_MSB():
    import sys # Temporary disabling python3 testing, something is going wrong in MO_MSB fuinction
    if sys.version_info[0] < 3:
        TV_0 = '01011111'
        FV_0 = '01001000'
        length = 4
        assert (RuleMngt.MO_MSB(TV_0, FV_0, 0, arg = 8 * 3))
        assert (not RuleMngt.MO_MSB(TV_0, FV_0, 0, arg = 8 * 4))

def test___init__():
    mgr = RuleMngt.RuleManager()
    assert (len(mgr.context) == 0)
    assert( "ignore" in mgr.MatchingOperators)
    assert( "equal" in mgr.MatchingOperators)
    assert( "match-mapping" in mgr.MatchingOperators)
    assert( "MSB" in mgr.MatchingOperators)

def test_addRule ():
    mgr = RuleMngt.RuleManager()
    rule = {"ruleid"  : 0,
                 "content" : [
    #               fID             Pos DI   TV                   MO        CDA
                    ["field1",      1,  "bi", 6,                  "equal",  "not-sent"],
                    ["field2",      1,  "up", 6,                  "equal",  "not-sent"],
                    ["field3",      1,  "do", 6,                "equal",  "not-sent"],
                    ["field4",      1,  "do", 6,                "equal",  "not-sent"],
                ]
    }
    mgr.addRule(rule)

    assert(len(mgr.context) == 1)
    assert(rule['upRules'] == 2)
    assert(rule['downRules'] == 3)

def test_addRule_doubleId ():
    mgr = RuleMngt.RuleManager()
    ruleId = 14
    rule = {"ruleid"  : ruleId,
                 "content" : [
    #               fID             Pos DI   TV                   MO        CDA
                    ["field1",      1,  "bi", 6,                  "equal",  "not-sent"],
                    ["field2",      1,  "up", 6,                  "equal",  "not-sent"],
                    ["field3",      1,  "do", 6,                "equal",  "not-sent"],
                    ["field4",      1,  "do", 6,                "equal",  "not-sent"],
                ]
    }
    mgr.addRule(rule)
    assert(len(mgr.context) == 1)
    with pytest.raises(ValueError) as exceptionInfo:
        mgr.addRule(rule)
    assert('Rule ID already exists' in str(exceptionInfo.value))
    assert(str(ruleId) in str(exceptionInfo.value))

def test_FindRuleFromID ():
    mgr = RuleMngt.RuleManager()
    ruleId = 14
    rule = {"ruleid"  : ruleId,
                 "content" : [
    #               fID             Pos DI   TV                   MO        CDA
                    ["field1",      1,  "bi", 6,                  "equal",  "not-sent"],
                    ["field2",      1,  "up", 6,                  "equal",  "not-sent"],
                    ["field3",      1,  "do", 6,                "equal",  "not-sent"],
                    ["field4",      1,  "do", 6,                "equal",  "not-sent"],
                ]
    }
    mgr.addRule(rule)
    assert(mgr.FindRuleFromID(ruleId) is not None)

def test_FindRuleFromHeader():
    mgr = RuleMngt.RuleManager()
    ruleId = 14
    rule = {"ruleid"  : ruleId,
                 "content" : [
    #               fID             Pos DI   TV                   MO        CDA
                    ["field1",      1,  "bi", 6,                  "equal",  "not-sent"],
                ]
    }
    mgr.addRule(rule)
    assert(mgr.FindRuleFromHeader({("field1", 1):"test"}, "up") is not None)

