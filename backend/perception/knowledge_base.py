"""
Ops Knowledge Base — error code → fault → solution association engine.

Loads YAML-defined knowledge association rules.
Matches perception data against known error patterns.
Returns structured fault descriptions for LLM reasoning.
"""
from __future__ import annotations
import re
import yaml
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class KnowledgeHit:
    error_pattern: str
    fault_type: str
    root_cause: str
    solution: str
    severity: str
    matched_text: str  # the actual text that triggered the match
    tags: list[str] = field(default_factory=list)


class OpsKnowledgeBase:
    """Loads and queries the ops knowledge base."""

    _instance = None

    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(__file__), "collection_rules.yaml"
            )
        self.rules_path = rules_path
        self.rules: list[dict] = []
        self._reload()

    def _reload(self):
        """Hot-reload rules from YAML. Safe for production use."""
        try:
            with open(self.rules_path, "r") as f:
                config = yaml.safe_load(f)
            self.rules = config.get("knowledge_association", {}).get("rules", [])
        except Exception:
            self.rules = []

    @classmethod
    def instance(cls) -> OpsKnowledgeBase:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def query_text(self, text: str) -> list[KnowledgeHit]:
        """Search for known error patterns in arbitrary text.
        Used by: log analysis, stderr parsing, user message analysis.
        """
        hits = []
        for rule in self.rules:
            pattern = rule.get("error_pattern", "")
            if not pattern:
                continue
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for m in matches:
                    hits.append(KnowledgeHit(
                        error_pattern=pattern,
                        fault_type=rule.get("fault_type", "Unknown"),
                        root_cause=rule.get("root_cause", ""),
                        solution=rule.get("solution", ""),
                        severity=rule.get("severity", "warn"),
                        matched_text=m.group(0)[:200],
                        tags=rule.get("tags", []),
                    ))
            except re.error:
                continue
        return hits

    def query_log_entries(self, entries: list) -> list[KnowledgeHit]:
        """Search for error patterns in structured log entries."""
        all_hits = []
        for entry in entries:
            text = entry.message if hasattr(entry, "message") else str(entry)
            hits = self.query_text(text)
            all_hits.extend(hits)
        return all_hits

    def query_tags(self, tags: list[str]) -> list[dict]:
        """Find rules matching specific tags (e.g., ['memory', 'crash'])."""
        results = []
        for rule in self.rules:
            rule_tags = set(rule.get("tags", []))
            if rule_tags & set(tags):
                results.append(rule)
        return results

    def get_knowledge_summary(self) -> str:
        """Compact summary for LLM prompt injection."""
        lines = ["## 运维知识库（错误码关联）\n"]
        lines.append("| 错误模式 | 故障类型 | 严重度 | 解决方案 |")
        lines.append("|---------|---------|--------|---------|")
        for rule in self.rules[:12]:
            pattern = rule.get("error_pattern", "")[:40]
            fault = rule.get("fault_type", "")[:12]
            sev = rule.get("severity", "")
            solution = rule.get("solution", "")[:50]
            lines.append(f"| {pattern} | {fault} | {sev} | {solution} |")
        return "\n".join(lines)

    def enrich_perception(self, perception_context) -> None:
        """Attach knowledge hits to a PerceptionContext in-place."""
        hits = []

        # Search log entries
        for entry in perception_context.logs.entries:
            hits.extend(self.query_text(entry.message))

        # Search anomaly descriptions
        for anomaly in perception_context.all_anomalies:
            hits.extend(self.query_text(anomaly))

        # Deduplicate
        seen = set()
        unique = []
        for h in hits:
            key = (h.fault_type, h.matched_text[:50])
            if key not in seen:
                seen.add(key)
                unique.append(h)

        perception_context.knowledge_hits = [
            {
                "fault_type": h.fault_type,
                "root_cause": h.root_cause,
                "solution": h.solution,
                "severity": h.severity,
                "matched_text": h.matched_text,
                "tags": h.tags,
            }
            for h in unique[:10]  # Limit for prompt size
        ]
