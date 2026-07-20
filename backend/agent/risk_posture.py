"""RiskPostureEngine — central bank of security posture.

Translates Malio's PersonaEngine pattern to security domain:
  energy/warmth/playfulness → restrictive/balanced/permissive
  Phillips Curve → Posture Trade-off (permissive → heavier audit)
  veto + alternative → block + suggest safe command
"""
import time
from datetime import datetime
from typing import Optional


class RiskPostureEngine:
    def __init__(self):
        self.posture = "balanced"
        self._veto_count = 0
        self._last_veto_time: Optional[float] = None
        self._last_posture_change = time.time()
        self._drift_log: list = []

    def set_posture(self, new: str, reason: str = ""):
        if new not in ("restrictive", "balanced", "permissive"):
            return
        old = self.posture
        self.posture = new
        self._last_posture_change = time.time()
        self._drift_log.append({
            "ts": datetime.now().isoformat(),
            "from": old, "to": new, "reason": reason,
        })
        if len(self._drift_log) > 50:
            self._drift_log = self._drift_log[-50:]

    def on_veto(self):
        self._veto_count += 1
        self._last_veto_time = time.time()
        if self._veto_count >= 2:
            self.set_posture("restrictive", f"连续{self._veto_count}次VETO")
        self._decay_veto_count()

    def on_permit(self):
        self._decay_veto_count()

    def _decay_veto_count(self):
        now = time.time()
        if self._last_veto_time and (now - self._last_veto_time) > 3600:
            self._veto_count = max(0, self._veto_count - 1)
            self._last_veto_time = now if self._veto_count > 0 else None

    def auto_regress(self):
        if self.posture != "balanced":
            elapsed = time.time() - self._last_posture_change
            if elapsed > 86400 and self._veto_count == 0:
                self.set_posture("balanced", "24h无异常，回归balanced")

    POSTURE_THRESHOLDS = {
        "restrictive": 0,
        "balanced": 5,
        "permissive": 7,
    }

    def time_based_posture(self, hour: int):
        if hour >= 22 or hour < 6:
            if self.posture == "permissive":
                self.set_posture("balanced", "深夜时段，限制permissive")

    def threshold_for_posture(self) -> dict:
        v = self.POSTURE_THRESHOLDS.get(self.posture, 5)
        return {"confirm": v, "description": f"T1≥{v}需确认"}

    def posture_for_prompt(self) -> dict:
        self._decay_veto_count()
        return {
            "posture": self.posture,
            "confirm_threshold": self.threshold_for_posture()["confirm"],
            "veto_count": self._veto_count,
            "audit_intensity": self.audit_intensity(),
            "text": (
                f"当前安全姿态: {self.posture}\n"
                f"确认阈值: T1≥{self.threshold_for_posture()['confirm']}需确认\n"
                f"近期VETO: {self._veto_count}次\n"
            ),
        }

    def audit_intensity(self) -> str:
        """Posture trade-off: permissive → heavier audit."""
        return {
            "restrictive": "summary",
            "balanced": "normal",
            "permissive": "full",
        }.get(self.posture, "normal")
