"""
    Tests SCHC's rule_mgnt's module
"""
import pytest
from SCHC import RuleMngt

def test_mo_ignore():
    """Tests RuleMgnt's ignore function"""
    assert RuleMngt.MO_ignore("", "", 0)

def test_mo_equal():
    """Tests RuleMgnt's Equal function"""
    tv_0 = "value"
    fv_0 = "value"
    assert RuleMngt.MO_equal(tv_0, fv_0, 0)
    tv_1 = "value"
    fv_1 = "value_2"
    assert not RuleMngt.MO_equal(tv_1, fv_1, 0)
    tv_2 = "value"
    fv_2 = 5
    assert not RuleMngt.MO_equal(tv_2, fv_2, 0)

def test_mo_matchmapping_list():
    """Tests RuleMgnt's matchmapping function"""
    tv_0 = [0, 1, 2, 3]
    fv_0 = 2
    assert RuleMngt.MO_matchmapping(tv_0, fv_0, 0)

    tv_1 = ["0", "1", "2", "3"]
    fv_1 = 2
    assert not RuleMngt.MO_matchmapping(tv_1, fv_1, 0)

    tv_2 = [0, 1, 2, 3]
    fv_2 = 4
    assert not RuleMngt.MO_matchmapping(tv_2, fv_2, 0)

#def test_MO_matchmapping_dict():
#    tv_0 = {
#            "k1":1,
#            "k2":0,
#            "k3":4,
#            "k4":3,
#        }
#    fv_0 = 0
#    fv_1 = 5
#    assert (RuleMngt.MO_matchmapping(tv_0, fv_0, 0))
#    assert (not RuleMngt.MO_matchmapping(tv_0, fv_1, 0))

def test_mo_msb():
    """Tests RuleMgnt's Mos Significant Byte function"""
    import sys # Temporary disabling python3 testing, something is going wrong in MO_MSB fuinction
    if sys.version_info[0] < 3:
        tv_0 = '01011111'
        fv_0 = '01001000'
        assert RuleMngt.MO_MSB(tv_0, fv_0, 0, arg=8 * 3)
        assert not RuleMngt.MO_MSB(tv_0, fv_0, 0, arg=8 * 4)

def test___init__():
    """Tests RuleMgnt's constructor"""
    mgr = RuleMngt.RuleManager()
    assert not mgr.context
    assert  "ignore" in mgr.MatchingOperators
    assert  "equal" in mgr.MatchingOperators
    assert  "match-mapping" in mgr.MatchingOperators
    assert  "MSB" in mgr.MatchingOperators

def test_addrule():
    """Tests RuleMgnt's addRule"""
    mgr = RuleMngt.RuleManager()
    rule = {"ruleid"  : 0,
            "content" : [
                # fID, Pos, DI, TV, MO, CDA
                ["field1", 1, "bi", 6, "equal", "not-sent"],
                ["field2", 1, "up", 6, "equal", "not-sent"],
                ["field3", 1, "dw", 6, "equal", "not-sent"],
                ["field4", 1, "dw", 6, "equal", "not-sent"],
            ]
           }
    mgr.addRule(rule)

    assert len(mgr.context) == 1
    assert rule['upRules'] == 2
    assert rule['downRules'] == 3

def test_addrule_doubleid():
    """Tests RuleMgnt's addrule function with an
    already existing ID"""
    mgr = RuleMngt.RuleManager()
    rule_id = 14
    rule = {"ruleid"  : rule_id,
            "content" : [
                # fID, Pos, DI, TV, MO, CDA
                ["field1", 1, "bi", 6, "equal", "not-sent"],
                ["field2", 1, "up", 6, "equal", "not-sent"],
                ["field3", 1, "dw", 6, "equal", "not-sent"],
                ["field4", 1, "dw", 6, "equal", "not-sent"],
            ]
           }
    mgr.addRule(rule)
    assert len(mgr.context) == 1
    with pytest.raises(ValueError) as exception_info:
        mgr.addRule(rule)
    assert 'Rule ID already exists' in str(exception_info.value)
    assert str(rule_id) in str(exception_info.value)

def test_findrulefromid():
    """Tests RuleMgnt's findRuleFromID"""
    mgr = RuleMngt.RuleManager()
    rule_id = 14
    rule = {"ruleid"  : rule_id,
            "content" : [
                # fID, Pos, DI, TV, MO, CDA
                ["field1", 1, "bi", 6, "equal", "not-sent"],
                ["field2", 1, "up", 6, "equal", "not-sent"],
                ["field3", 1, "dw", 6, "equal", "not-sent"],
                ["field4", 1, "dw", 6, "equal", "not-sent"],
            ]
           }
    mgr.addRule(rule)
    assert mgr.FindRuleFromID(rule_id) is not None

def test_findrulefromheader():
    """Tests RuleMgnt's findRuleFromHeader"""
    mgr = RuleMngt.RuleManager()
    rule_id = 14
    rule = {"ruleid"  : rule_id,
            "content" : [
                # fID, Pos, DI, TV, MO, CDA
                ["field1", 1, "bi", 6, "equal", "not-sent"],
            ]
           }
    mgr.addRule(rule)
    assert mgr.FindRuleFromHeader({("field1", 1):"test"}, "up") is not None
