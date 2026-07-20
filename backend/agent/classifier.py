"""Lightweight LLM intent classifier — replaces keyword Router.

Uses a tiny dedicated prompt to classify user input as query | action | emergency.
Returns only a label — no JSON, no reasoning — keeping latency near-zero.
Falls back to rule-based keywords when AGENT_MODE=mock (no LLM available).
"""
import json
from agent.router import Router


CLASSIFIER_PROMPT = """你是意图分类器。将用户输入归类为以下三种之一:

query    — 用户只想查看/查询/了解，不需要修改系统
action   — 用户想要修改/重启/删除/安装/配置系统
emergency — 系统宕机/崩溃/数据丢失/磁盘满/无法访问

规则:
- 如果只是问状态、查看、了解情况 → query
- 如果明确要求执行操作 → action
- 如果是紧急故障告警 → emergency
- "帮我看看需不需要X" = query（用户还没决定要做）
- "帮我X" = action（用户明确要求执行）

返回格式: 只返回一个词: query、action 或 emergency。不要返回任何其他文字。"""


class Classifier:
    """LLM-based classifier with rule fallback."""

    def __init__(self, provider_registry, config_mode: str = "default"):
        self.provider_registry = provider_registry
        self._rule_classifier = Router()
        self._use_llm = config_mode != "mock"

    def classify(self, user_input: str, _ctx: dict = None) -> dict:
        if not self._use_llm:
            return self._rule_classifier.classify(user_input)

        try:
            provider = self.provider_registry.get_active()
            if provider is None:
                return self._rule_classifier.classify(user_input)

            raw = provider.generate(CLASSIFIER_PROMPT, user_input)
            label = raw.strip().lower()

            if "emergency" in label:
                return {"mode": "emergency", "trigger": "llm_classified"}
            if "action" in label:
                return {"mode": "action", "trigger": "llm_classified"}
            return {"mode": "query", "trigger": "llm_classified"}

        except Exception:
            return self._rule_classifier.classify(user_input)
