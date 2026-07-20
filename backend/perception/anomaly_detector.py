"""
Anomaly Detector — Level 2 predefined pattern + Level 1 statistical baseline.

Loads YAML anomaly_rules. Evaluates conditions against PerceptionContext.
Returns structured anomaly reports for the reasoner.
"""
from __future__ import annotations
import yaml
import os
import operator as op
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class AnomalyReport:
    rule_name: str
    description: str
    severity: str          # ok / warn / critical
    suggestion: str
    matched_field: str
    matched_value: Any
    threshold: Any


class AnomalyDetector:
    """Evaluates predefined anomaly rules against a PerceptionContext."""

    OPERATORS = {
        ">": op.gt, ">=": op.ge, "<": op.lt, "<=": op.le,
        "==": op.eq, "!=": op.ne,
    }

    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(__file__), "collection_rules.yaml"
            )
        self.rules_path = rules_path
        self.rules: list[dict] = []
        self._reload()

    def _reload(self):
        try:
            with open(self.rules_path, "r") as f:
                config = yaml.safe_load(f)
            self.rules = config.get("anomaly_rules", [])
        except Exception:
            self.rules = []

    def _resolve_field(self, ctx, field_path: str) -> Any:
        """Resolve a dotted field path with wildcards, arithmetic, and filters.

        Supported:
          - Simple: memory.memory.use_percent
          - Wildcard: disks.volumes[*].use_percent → returns list of all matches
          - Filter: files.temp_files[size > 1GB] → returns matching items
          - Arithmetic: memory.memory.swap_used_gb / memory.memory.total_gb
        """
        import re

        # Handle arithmetic expressions (only simple a / b for now)
        if " / " in field_path or " + " in field_path or " * " in field_path:
            return self._eval_arithmetic(ctx, field_path)

        parts = field_path.split(".")
        obj = ctx
        for part in parts:
            if obj is None:
                return None

            # Wildcard: field[*].subfield
            if part == "[*]":
                continue  # wildcard means "iterate over all items" — handled by parent

            # Filter: field[condition]
            filter_match = re.match(r'(\w+)\[(.+)\]', part)
            if filter_match:
                attr_name = filter_match.group(1)
                condition = filter_match.group(2)
                obj = getattr(obj, attr_name, None)
                if obj is None or not isinstance(obj, list):
                    return None
                # Apply filter: e.g. "size > 1073741824", "path contains core"
                obj = self._apply_list_filter(obj, condition)
                continue

            # Array index: field[0]
            idx_match = re.match(r'(\w+)\[(\d+)\]', part)
            if idx_match:
                obj = getattr(obj, idx_match.group(1), None)
                if obj is None:
                    return None
                obj = obj[int(idx_match.group(2))]
                continue

            obj = getattr(obj, part, None)

        return obj

    def _eval_arithmetic(self, ctx, expr: str) -> Any:
        """Evaluate simple arithmetic on resolved fields: 'a.use / b.use'."""
        import re
        tokens = re.split(r' ([/+*-]) ', expr)
        values = []
        for token in tokens:
            token = token.strip()
            if token in ("/", "+", "-", "*"):
                values.append(token)
            else:
                val = self._resolve_field(ctx, token)
                if val is None:
                    return None
                values.append(val)

        try:
            result = values[0]
            for i in range(1, len(values), 2):
                op = values[i]
                operand = values[i + 1]
                if op == "/":
                    result = result / operand if operand else 0
                elif op == "+":
                    result = result + operand
                elif op == "-":
                    result = result - operand
                elif op == "*":
                    result = result * operand
            return result
        except (TypeError, ZeroDivisionError):
            return None

    def _apply_list_filter(self, items: list, condition: str) -> list:
        """Filter a list by condition: 'size > 1GB', 'path contains core'."""
        import re
        results = []

        # Parse: field op value
        cond_match = re.match(r'(\w+)\s*(>|<|>=|<=|==|!=|contains)\s*(.+)', condition)
        if not cond_match:
            return items

        field, op_str, value_str = cond_match.group(1), cond_match.group(2), cond_match.group(3).strip()

        # Parse value — handle "1GB", "100MB" etc
        multiplier = 1
        if value_str.upper().endswith("GB"):
            multiplier = 1024**3
            value_str = value_str[:-2]
        elif value_str.upper().endswith("MB"):
            multiplier = 1024**2
            value_str = value_str[:-2]
        elif value_str.upper().endswith("KB"):
            multiplier = 1024
            value_str = value_str[:-2]

        try:
            threshold = float(value_str) * multiplier
        except ValueError:
            threshold = value_str  # string comparison

        for item in items:
            if isinstance(item, dict):
                item_val = item.get(field)
            else:
                item_val = getattr(item, field, None)

            if item_val is None:
                continue

            if op_str == "contains":
                if isinstance(threshold, str) and threshold.lower() in str(item_val).lower():
                    results.append(item)
            elif op_str == ">":
                if isinstance(item_val, (int, float)) and item_val > threshold:
                    results.append(item)
            elif op_str == "<":
                if isinstance(item_val, (int, float)) and item_val < threshold:
                    results.append(item)
            elif op_str == ">=":
                if isinstance(item_val, (int, float)) and item_val >= threshold:
                    results.append(item)
            elif op_str == "<=":
                if isinstance(item_val, (int, float)) and item_val <= threshold:
                    results.append(item)
            elif op_str == "==":
                if str(item_val) == str(threshold):
                    results.append(item)
            elif op_str == "!=":
                if str(item_val) != str(threshold):
                    results.append(item)

        return results

    def _evaluate_condition(self, ctx, rule: dict) -> Optional[dict]:
        """Evaluate a single rule condition. Returns match info or None."""
        field_path = rule.get("condition", {}).get("field", "")
        operator_str = rule.get("condition", {}).get("operator", ">")
        threshold = rule.get("condition", {}).get("value")

        # Handle "changed" and "exists" operators
        if operator_str == "changed":
            return None  # Requires baseline comparison — skip for now
        if operator_str == "exists":
            value = self._resolve_field(ctx, field_path)
            if value and (isinstance(value, list) and len(value) > 0):
                return {"field": field_path, "value": f"found {len(value)} items", "threshold": threshold}
            return None

        value = self._resolve_field(ctx, field_path)
        if value is None:
            return None

        # Handle wildcard results (list from [*] expansion)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, (int, float)):
                    try:
                        if self.OPERATORS.get(operator_str, lambda a, b: False)(item, threshold):
                            return {"field": field_path, "value": item, "threshold": threshold}
                    except (TypeError, ValueError):
                        continue
            return None

        comparator = self.OPERATORS.get(operator_str)
        if comparator is None:
            return None

        # Handle special thresholds
        if isinstance(threshold, str) and "baseline" in threshold:
            return None

        try:
            if comparator(value, threshold):
                return {"field": field_path, "value": value, "threshold": threshold}
        except (TypeError, ValueError):
            pass
        return None

    def evaluate(self, perception_context) -> list[AnomalyReport]:
        """Run all anomaly rules against a PerceptionContext."""
        reports = []
        for rule in self.rules:
            try:
                match = self._evaluate_condition(perception_context, rule)
                if match:
                    reports.append(AnomalyReport(
                        rule_name=rule.get("name", "unknown"),
                        description=rule.get("description", ""),
                        severity=rule.get("severity", "warn"),
                        suggestion=rule.get("suggestion", ""),
                        matched_field=match["field"],
                        matched_value=match["value"],
                        threshold=match["threshold"],
                    ))
            except Exception:
                continue
        return reports

    def enrich_perception(self, perception_context) -> None:
        """Attach anomaly reports to a PerceptionContext in-place."""
        reports = self.evaluate(perception_context)
        perception_context.all_anomalies = [
            f"[{r.severity.upper()}] {r.description}: {r.matched_field}={r.matched_value} (阈值={r.threshold}). {r.suggestion}"
            for r in reports
        ]
        # Also attach to sub-snapshots
        for r in reports:
            if "process" in r.rule_name:
                perception_context.processes.anomalies.append(r.description)
            elif "service" in r.rule_name:
                perception_context.services.anomalies.append(r.description)
            elif "disk" in r.rule_name or "inode" in r.rule_name:
                perception_context.disks.anomalies.append(r.description)
            elif "memory" in r.rule_name or "swap" in r.rule_name:
                perception_context.memory.anomalies.append(r.description)
            elif "network" in r.rule_name or "port" in r.rule_name:
                perception_context.network.anomalies.append(r.description)
            elif "log" in r.rule_name:
                pass  # Log anomalies are severity-only
            elif "file" in r.rule_name:
                perception_context.files.anomalies.append(r.description)
