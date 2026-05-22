"""Quick verification of night posture fix."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.risk_posture import RiskPostureEngine

e = RiskPostureEngine()

# Test hour 22 — should trigger nighttime suppression
e.set_posture("permissive", "test")
e.time_based_posture(22)
assert e.posture == "balanced", f"hour 22 should trigger nighttime, got {e.posture}"
print("PASS: hour 22 triggers nighttime")

# Test hour 21 — should NOT trigger
e.set_posture("permissive", "test")
e.time_based_posture(21)
assert e.posture == "permissive", f"hour 21 should NOT trigger, got {e.posture}"
print("PASS: hour 21 does NOT trigger nighttime")

# Test hour 6 — should NOT trigger (boundary)
e.set_posture("permissive", "test")
e.time_based_posture(6)
assert e.posture == "permissive", f"hour 6 should NOT trigger, got {e.posture}"
print("PASS: hour 6 does NOT trigger (boundary)")

# Test hour 5 — should trigger
e.set_posture("permissive", "test")
e.time_based_posture(5)
assert e.posture == "balanced", f"hour 5 should trigger nighttime, got {e.posture}"
print("PASS: hour 5 triggers nighttime")

# Test hour 23 — should trigger
e.set_posture("permissive", "test")
e.time_based_posture(23)
assert e.posture == "balanced", f"hour 23 should trigger nighttime, got {e.posture}"
print("PASS: hour 23 triggers nighttime")

# Balanced posture should stay balanced during nighttime
e.set_posture("balanced", "test")
e.time_based_posture(22)
assert e.posture == "balanced", f"balanced should stay, got {e.posture}"
print("PASS: balanced stays balanced at night")

print("\nAll 6 night posture tests passed!")
