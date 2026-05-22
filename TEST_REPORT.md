# Kylin-Agent 测试报告

**生成时间**：2026-05-20  
**平台**：Kylin Linux Advanced Server V11 (Swan25) · Python 3.11.6 · LoongArch/x86_64  
**结果**：62 passed · 0 failed · 0.35s

---

## 测试概览

| 文件 | 数量 | 覆盖范围 |
|------|:----:|---------|
| `test_guardrail.py` | 15 | T0→T3 安全护栏全层 |
| `test_jailbreak.py` | 4 | 越狱攻击向量 + 结构性免疫 |
| `test_pessimistic.py` | 24 | 悲观路径、并发、边界、Manifest |
| `test_pipeline.py` | 11 | 流水线集成 + 审计链 |
| `test_risk_posture.py` | 8 | RiskPostureEngine 状态机 |
| **总计** | **62** | |

---

## test_guardrail.py — 安全护栏 (15 tests)

| 测试 | 说明 |
|------|------|
| `test_t0_clean_input_passes` | 正常中文运维指令通过 |
| `test_t0_role_switch_blocked` | "ignore all previous instructions" 阻断 |
| `test_t0_delimiter_blocked` | `[INST]` / `[/INST]` 分隔符阻断 |
| `test_t0_overflow_blocked` | 超过 8000 字符输入阻断 |
| `test_t1_readonly_scores_low` | `systemctl status` 风险评分 ≤ 2 |
| `test_t1_rm_rf_scores_critical` | `rm -rf /var/log` 风险评分 ≥ 5 |
| `test_t1_destructive_scores_max` | `rm -rf /` 风险评分 == 10 |
| `test_t2_veto_dangerous_command` | T2 阻止危险命令 |
| `test_t2_confirm_high_risk` | 高风险命令触发确认要求 |
| `test_t2_permissive_skips_confirm` | Permissive 模式跳过低风险确认 |
| `test_t2_restrictive_requires_confirm_early` | Restrictive 模式提前要求确认 |
| `test_t3_ps_is_allowed` | `ps` 在沙箱白名单内 |
| `test_t3_rm_is_not_allowed` | `rm` 被沙箱拒绝 |
| `test_veto_suggests_alternative` | 拦截时给出安全替代方案 |
| `test_fork_bomb_blocked` | Fork 炸弹模式被拦截 |

## test_jailbreak.py — 越狱免疫 (4 tests)

| 测试 | 说明 |
|------|------|
| `test_t0_blocks_all_attacks` | 10 种越狱向量全部被 T0 拦截 |
| `test_t2_blocks_dangerous_even_if_t0_passes` | T0 被绕过后 T2 仍拦截危险命令 |
| `test_t1_scores_critical_correctly` | T1 对危险指令正确打高分 |
| `test_structural_immunity` | T0 + T2 提供结构性纵深防御 |

## test_pessimistic.py — 悲观路径 (24 tests)

### T0 注入绕过

| 测试 | 说明 |
|------|------|
| `test_t0_zero_width_chars_stripped` | U+200B 零宽空格剥离后正则匹配 |
| `test_t0_unicode_confusable_normalized` | 全角字符 NFKC 正规化 (ｐ→p) |
| `test_t0_short_base64_blocked` | 短 base64 payload (10+ 字符) 检测 |
| `test_t0_clean_chinese_not_blocked` | 正常中文 "查看被杀掉的进程" 不误杀 |

### T1 边界

| 测试 | 说明 |
|------|------|
| `test_t1_empty_command` | 空命令不崩溃 |
| `test_t1_unknown_command` | 未知命令默认风险评分 |

### T2 结构性验证

| 测试 | 说明 |
|------|------|
| `test_t2_structured_tool_call_with_dangerous_path` | `cat /etc/shadow` 结构性拦截 |
| `test_t2_structured_tool_call_benign` | 正常 `ps limit=10` 放行 |
| `test_t2_restrictive_mode_blocks_everything` | Restrictive 全面启用 |

### T3 沙箱

| 测试 | 说明 |
|------|------|
| `test_t3_empty_command` | 空命令被沙箱拒绝 |
| `test_t3_nonexistent_command` | 不存在命令被沙箱拒绝 |
| `test_t3_ps_in_allowlist` | 工具名正确匹配 allowlist |
| `test_t3_resolve_cmd_all_tools` | 9 个工具 param_flags 翻译全正确 |
| `test_t3_resolve_cmd_unknown_tool` | 未知工具名透传不崩溃 |

### 姿态引擎

| 测试 | 说明 |
|------|------|
| `test_posture_invalid_rejected` | 非法姿态名称被拒绝 |
| `test_posture_decay_veto_count` | Veto 计数 1 小时后衰减 |
| `test_posture_thresholds_consistent` | 三态阈值在 0-10 范围内 |
| `test_posture_auto_regress_to_balanced` | 24h 无异常自动回归 balanced |

### Manifest 一致性

| 测试 | 说明 |
|------|------|
| `test_manifest_no_duplicate_llm_names` | LLM 工具名无重复 |
| `test_manifest_all_have_required_fields` | 每条 10 个必需字段齐全 |
| `test_manifest_param_flags_valid` | `param_flags` 值格式合法 |

### 并发与容错

| 测试 | 说明 |
|------|------|
| `test_sanitizer_concurrent_calls` | 4 线程 × 50 次 并发 `sanitize()` 无崩溃 |
| `test_mock_provider_handles_unknown_input` | 未识别输入安全回落 `general_query` |
| `test_mock_provider_returns_valid_json` | 7 种输入全返回合法 JSON |

## test_pipeline.py — 流水线集成 (11 tests)

| 测试 | 说明 |
|------|------|
| `test_perception_builds_context` | 感知层上下文构建正确 |
| `test_perception_mock_has_data` | Mock 传感器返回完整假数据 |
| `test_router_classifies_query` | 路由识别查询意图 |
| `test_router_classifies_action` | 路由识别操作意图 |
| `test_router_classifies_emergency` | 路由识别紧急意图 |
| `test_router_classifies_help` | 路由识别帮助意图 |
| `test_t0_rejects_injection` | 流水线中 T0 注入拦截 |
| `test_hash_chain_integrity` | SHA256 审计链完整性 |
| `test_hash_chain_detects_tamper` | 审计链篡改检测 |
| `test_audit_store_writes` | 审计事件成功落盘 JSONL |
| `test_router_unknown_input` | 未知输入路由不崩溃 |

## test_risk_posture.py — 姿态引擎 (8 tests)

| 测试 | 说明 |
|------|------|
| `test_default_posture_is_balanced` | 初始姿态为 balanced |
| `test_threshold_for_balanced` | Balanced 确认阈值 = 5 |
| `test_threshold_for_restrictive` | Restrictive 确认阈值 = 0 |
| `test_threshold_for_permissive` | Permissive 确认阈值 = 7 |
| `test_double_veto_downgrades_to_restrictive` | 连续 2 次 veto → restrictive |
| `test_audit_intensity_tradeoff` | Permissive → full audit |
| `test_time_based_posture_at_night` | 深夜 23:00-06:00 限制 permissive |
| `test_invalid_posture_rejected` | 无效姿态设置被忽略 |

---

## 覆盖矩阵

| 层级 | 快乐路径 | 悲观路径 | 并发 |
|------|:--------:|:--------:|:----:|
| T0 注入检测 | 5 | 4 | 1 |
| T1 风险评分 | 3 | 2 | — |
| T2 约束引擎 | 4 | 3 | — |
| T3 沙箱 | 2 | 5 | — |
| 姿态引擎 | 8 | 4 | — |
| 流水线/审计 | 11 | — | — |
| Manifest | — | 3 | — |
| Provider | 2 | — | — |

---

## 运行方式

```bash
cd backend
python3 -m pytest tests/ -v
```

或单独运行：

```bash
python3 -m pytest tests/test_guardrail.py -v
python3 -m pytest tests/test_jailbreak.py -v
python3 -m pytest tests/test_pessimistic.py -v
python3 -m pytest tests/test_pipeline.py -v
python3 -m pytest tests/test_risk_posture.py -v
```
