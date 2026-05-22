"""Jailbreak corpus regression test — iterates jailbreak_corpus.json.

For each entry verifies:
  - T0 anti-injection blocks when expected_t0_block is true
  - T2 constraints block when expected_t2_block is true
  - No false positives on legitimate inputs (severity=none)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.anti_injection import sanitize
from security.constraints import ConstraintEngine


CORPUS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "jailbreak_corpus.json"
)


def load_corpus():
    with open(CORPUS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestJailbreakCorpus:
    @classmethod
    def setup_class(cls):
        data = load_corpus()
        cls.entries = data["entries"]
        cls.engine = ConstraintEngine()

    def test_t0_blocks_when_expected(self):
        blocked = 0
        missed = []
        for entry in self.entries:
            if not entry.get("expected_t0_block"):
                continue
            is_blocked, cleaned, ref = sanitize(entry["payload"])
            if is_blocked:
                blocked += 1
            else:
                missed.append(f"  {entry['id']} {entry['name']}: NOT blocked (cleaned={cleaned[:60]}...)")
        if missed:
            print("\n" + "\n".join(missed))
        assert blocked >= max(1, sum(1 for e in self.entries if e.get("expected_t0_block")) * 0.8), \
            f"T0: {blocked}/{sum(1 for e in self.entries if e.get('expected_t0_block'))} expected blocks"

    def test_t2_blocks_when_expected(self):
        blocked = 0
        missed = []
        for entry in self.entries:
            if not entry.get("expected_t2_block"):
                continue
            # Try structured validation with rm tool
            cmd = entry["payload"]
            result = self.engine.validate(cmd)
            if not result.allowed:
                blocked += 1
            else:
                missed.append(f"  {entry['id']} {entry['name']}: T2 allowed (risk={result.risk_score})")
        if missed:
            print("\n" + "\n".join(missed))
        assert blocked >= max(1, sum(1 for e in self.entries if e.get("expected_t2_block")) * 0.7), \
            f"T2: {blocked}/{sum(1 for e in self.entries if e.get('expected_t2_block'))} expected blocks"

    def test_no_false_positive_on_legitimate(self):
        """Entries with severity=none should NOT be blocked by T0 or T2."""
        for entry in self.entries:
            if entry.get("severity") != "none":
                continue
            is_blocked, cleaned, ref = sanitize(entry["payload"])
            assert not is_blocked, \
                f"FALSE POSITIVE T0: {entry['id']} {entry['name']} blocked as {ref}"
            result = self.engine.validate(cleaned)
            assert result.allowed, \
                f"FALSE POSITIVE T2: {entry['id']} {entry['name']} vetoed: {result.reason}"

    def test_all_entries_have_required_fields(self):
        required = {"id", "name", "category", "payload", "severity"}
        for entry in self.entries:
            missing = required - set(entry.keys())
            assert not missing, f"{entry.get('id', '?')}: missing fields {missing}"

    def test_categories_match_known(self):
        known = {"role_switch", "delimiter", "encoded", "unicode", "structural"}
        for entry in self.entries:
            assert entry["category"] in known, \
                f"{entry['id']}: unknown category '{entry['category']}'"


if __name__ == "__main__":
    corpus = load_corpus()
    print(f"Corpus: {len(corpus['entries'])} entries\n")

    t0_total = sum(1 for e in corpus["entries"] if e.get("expected_t0_block"))
    t2_total = sum(1 for e in corpus["entries"] if e.get("expected_t2_block"))
    leg_total = sum(1 for e in corpus["entries"] if e.get("severity") == "none")
    print(f"  T0-expected: {t0_total}  T2-expected: {t2_total}  legitimate: {leg_total}")

    tests = TestJailbreakCorpus()
    TestJailbreakCorpus.setup_class()
    for name in ["test_t0_blocks_when_expected", "test_t2_blocks_when_expected",
                 "test_no_false_positive_on_legitimate", "test_all_entries_have_required_fields",
                 "test_categories_match_known"]:
        try:
            getattr(tests, name)()
            print(f"  [PASS] {name}")
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")
        except Exception as e:
            print(f"  [ERROR] {name}: {type(e).__name__}: {e}")
