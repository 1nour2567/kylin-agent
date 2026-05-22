"""RiskPostureEngine tests."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.risk_posture import RiskPostureEngine


def test_default_posture_is_balanced():
    engine = RiskPostureEngine()
    assert engine.posture == "balanced"


def test_threshold_for_balanced():
    engine = RiskPostureEngine()
    t = engine.threshold_for_posture()
    assert t["confirm"] == 5


def test_threshold_for_restrictive():
    engine = RiskPostureEngine()
    engine.set_posture("restrictive", "test")
    assert engine.threshold_for_posture()["confirm"] == 0


def test_threshold_for_permissive():
    engine = RiskPostureEngine()
    engine.set_posture("permissive", "test")
    assert engine.threshold_for_posture()["confirm"] == 7


def test_double_veto_downgrades_to_restrictive():
    engine = RiskPostureEngine()
    engine.on_veto()
    assert engine.posture == "balanced"
    engine.on_veto()
    assert engine.posture == "restrictive"


def test_audit_intensity_tradeoff():
    engine = RiskPostureEngine()
    assert engine.audit_intensity() == "normal"
    engine.set_posture("permissive", "test")
    assert engine.audit_intensity() == "full"
    engine.set_posture("restrictive", "test")
    assert engine.audit_intensity() == "summary"


def test_time_based_posture_at_night():
    engine = RiskPostureEngine()
    engine.set_posture("permissive", "test")
    engine.time_based_posture(2)
    assert engine.posture == "balanced"


def test_invalid_posture_rejected():
    engine = RiskPostureEngine()
    engine.set_posture("dangerous", "test")
    assert engine.posture == "balanced"


if __name__ == "__main__":
    tests = [
        test_default_posture_is_balanced,
        test_threshold_for_balanced, test_threshold_for_restrictive,
        test_threshold_for_permissive, test_double_veto_downgrades_to_restrictive,
        test_audit_intensity_tradeoff, test_time_based_posture_at_night,
        test_invalid_posture_rejected,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"[PASS] {t.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
