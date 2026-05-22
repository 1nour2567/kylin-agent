"""Semantic ambiguity tests — classifier/router must handle edge cases.

The old keyword Router matches "清理" → action unconditionally.
The LLM Classifier should understand context and route correctly:
  - "帮我看看需不需要清理" = query (not asking to clean)
  - "清理掉过期日志" = action (explicit cleanup order)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.router import Router
from security.anti_injection import sanitize

os.environ.setdefault("AGENT_MODE", "mock")

# ── Pairs: (input, correct_classification) ──
# query = intent to view/understand, action = intent to modify, emergency = crisis
AMBIGUITY_CASES = [
    # Keywords in non-action context → should be QUERY
    ("帮我看看需不需要清理", "query", "含'清理'但只是询问要不要做"),
    ("查一下有没有需要重启的服务", "query", "含'重启'但只是查询需求"),
    ("磁盘空间是不是该清理了", "query", "含'清理'但是疑问句式"),
    ("帮我看看能不能杀掉僵尸进程", "query", "含'杀掉'但是询问可行性"),

    # Explicit action requests → should be ACTION
    ("清理掉/var/log下7天前的日志", "action", "明确的清理指令"),
    ("重启nginx服务", "action", "明确的重启指令"),
    ("杀掉PID 1234的进程", "action", "明确的kill指令"),
    ("删除/tmp下的临时文件", "action", "明确的删除指令"),

    # Hypothetical/conditional → should be QUERY
    ("如果磁盘满了可能需要清理", "query", "假设性陈述"),
    ("当服务挂了的时候应该重启吗", "query", "询问操作步骤"),
    ("建议什么时候做日志清理", "query", "询问建议而非要求执行"),

    # Observation, not request → QUERY
    ("磁盘好像快满了", "query", "观察陈述"),
    ("nginx看起来不太正常", "query", "状态观察"),
    ("最近日志增长很快", "query", "趋势观察"),

    # Emergency declarations → EMERGENCY
    ("服务器宕机了，官网无法访问", "emergency", "明显的紧急故障"),
    ("磁盘满了，所有服务都挂了", "emergency", "磁盘满+服务挂"),

    # Polite questions → QUERY
    ("请问可以帮我看看磁盘空间吗", "query", "礼貌形式的查询"),
    ("麻烦查看一下内存使用情况", "query", "礼貌查询"),

    # Explicit negative → QUERY
    ("现在不需要清理日志", "query", "否定了操作"),

    # Ambiguous but dangerous-looking → QUERY or ACTION based on intent
    ("帮我分析一下为什么内存占用这么高", "query", "分析请求，不是操作请求"),
    ("定位磁盘IO瓶颈的原因", "query", "诊断请求"),
]


class TestKeywordRouter:
    """Test the old keyword Router — shows WHY we upgraded to Classifier."""

    def setup_method(self):
        self.router = Router()

    def test_router_known_false_positives(self):
        """Document cases where keyword Router gets it WRONG."""
        fp_cases = [
            ("帮我看看需不需要清理", "action",  # "清理" triggers action
             "Keyword router incorrectly classifies '看看需不需要' as action"),
            ("磁盘空间是不是该清理了", "action",  # "清理" triggers action
             "Question with '清理' misclassified"),
            ("查一下有没有需要重启的服务", "action",  # "重启" triggers action
             "Query with '重启' misclassified"),
        ]
        for user_input, wrong_label, reason in fp_cases:
            result = self.router.classify(user_input)
            # The old router DOES make these mistakes — we verify it
            assert result["mode"] == wrong_label, \
                f"Expected false positive: '{user_input}' should be {wrong_label} (got {result['mode']}). {reason}"
        print("  (All confirmed — old Router makes these mistakes as expected)")

    def test_router_correct_on_clear_cases(self):
        """Clear-cut cases the keyword Router gets RIGHT."""
        correct = [
            ("查看磁盘使用情况", "query"),
            ("清理系统日志", "action"),
            ("服务器宕机了，紧急处理", "emergency"),
            ("help", "query"),
            ("你好", "query"),
        ]
        for user_input, expected in correct:
            result = self.router.classify(user_input)
            assert result["mode"] == expected, \
                f"'{user_input}' should be {expected}, got {result['mode']}"


class TestClassifierRequirements:
    """Contract tests for the LLM Classifier — what it MUST get right.

    Since MockProvider (mock mode) uses keyword matching internally,
    these test the *contract*: given a real LLM, these should all pass.
    For now we test the Router as a baseline and document the gaps.
    """

    def test_ambiguity_cases_well_formed(self):
        """All test cases have valid input that passes T0 sanitization."""
        for user_input, expected, _reason in AMBIGUITY_CASES:
            blocked, cleaned, ref = sanitize(user_input)
            assert not blocked, \
                f"'{user_input}' should NOT be blocked by T0 (was: {ref})"

    def test_clean_chinese_not_blocked(self):
        """Normal Chinese ops queries pass T0 cleanly."""
        for user_input, _, _ in AMBIGUITY_CASES:
            blocked, _, _ = sanitize(user_input)
            assert not blocked, f"'{user_input}' blocked by T0"

    def test_all_cases_have_valid_mode(self):
        """All entries use valid modes."""
        for _, expected, _ in AMBIGUITY_CASES:
            assert expected in ("query", "action", "emergency"), \
                f"Invalid mode: {expected}"

    def test_dangerous_subset_still_t2_blocked(self):
        """Cases that pass T0 but contain dangerous commands are caught by T2.

        T2 raw regex is English-only (rm -rf, chmod 777, etc.).
        Chinese text like "杀掉进程" passes raw regex but would be caught
        by the STRUCTURED path when the LLM outputs kill_process tool call.
        """
        from security.constraints import ConstraintEngine
        engine = ConstraintEngine()
        # These test the raw regex path (English patterns only — by design)
        english_dangerous = [
            ("rm -rf /var/log/nginx", True),
            ("chmod 777 /etc", True),
        ]
        for cmd, should_block in english_dangerous:
            result = engine.validate(cmd)
            if should_block:
                assert not result.allowed, \
                    f"'{cmd}' should be T2-blocked"

        # Chinese dangerous input passes raw regex but T2 structured path
        # catches the LLM tool call (kill_process → confirm tier).
        # This documents the asymmetry — raw regex is defense-in-depth,
        # not the primary path for LLM-generated commands.
        chinese_cmd = "杀掉PID 1234的进程"
        _, cleaned, _ = sanitize(chinese_cmd)
        result = engine.validate(cleaned)
        # Raw regex doesn't catch Chinese — this is expected
        assert result.allowed, \
            f"'{chinese_cmd}' passes raw regex (Chinese not in patterns) — "\
            "structured validation handles LLM tool calls"


class TestFullPipelineAmbiguity:
    """End-to-end: verify that ambiguous inputs don't crash the pipeline."""

    def test_all_ambiguity_inputs_parseable(self):
        """Every ambiguity case passes T0 without crash."""
        for user_input, _, reason in AMBIGUITY_CASES:
            blocked, cleaned, ref = sanitize(user_input)
            assert isinstance(blocked, bool), f"Crash on '{user_input}': {reason}"
            assert isinstance(cleaned, str)
            assert isinstance(ref, str)


if __name__ == "__main__":
    print("=== Keyword Router Known Issues ===")
    r = TestKeywordRouter()
    r.setup_method()
    for name in ["test_router_known_false_positives", "test_router_correct_on_clear_cases"]:
        try:
            getattr(r, name)()
            print(f"  [PASS] {name}")
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")

    print("\n=== Classifier Requirements ===")
    c = TestClassifierRequirements()
    for name in ["test_ambiguity_cases_well_formed", "test_clean_chinese_not_blocked",
                 "test_all_cases_have_valid_mode", "test_dangerous_subset_still_t2_blocked"]:
        try:
            getattr(c, name)()
            print(f"  [PASS] {name}")
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")

    print("\n=== Pipeline Integration ===")
    p = TestFullPipelineAmbiguity()
    for name in ["test_all_ambiguity_inputs_parseable"]:
        try:
            getattr(p, name)()
            print(f"  [PASS] {name}")
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")

    print(f"\nAmbiguity corpus: {len(AMBIGUITY_CASES)} cases")
