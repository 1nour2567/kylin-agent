# Kylin-Agent 测试报告

**生成时间**：2026-05-21  
**平台**：Kylin Linux Advanced Server V11 (Swan25) · Python 3.11.6 · x86_64  
**结果**：135 passed · 0 failed · ~1s

---

## 测试概览

| 文件 | 数量 | 覆盖范围 |
|------|:----:|---------|
| `test_guardrail.py` | 15 | T0→T3 安全护栏全层 |
| `test_pipeline.py` | 11 | 流水线集成 + 审计链 |
| `test_risk_posture.py` | 8 | RiskPostureEngine 状态机 |
| `test_jailbreak.py` | 4 | 已知越狱攻击向量 + 结构免疫 |
| `test_jailbreak_corpus.py` | 5 | 35 条越狱语料库回归测试 |
| `test_key_auth.py` | 17 | KeyStore CRUD + 角色阈值 + 权限测试 |
| `test_confirm_audit_api.py` | 9 | 确认/拒绝流程 + 审计端点 + 角色门控 |
| `test_api.py` | 11 | HTTP 级别集成测试 |
| `test_pessimistic.py` | 19 | 悲观路径、并发、Manifest 一致性、Provider 容错 |
| `test_session_store.py` | 10 | 会话 TTL、对话历史、并发安全 |
| `test_semantic_ambiguity.py` | 7 | 中文语义歧义语料库（25 条）+ 分类器契约 |
| `test_baseline.py` | 9 | 审计基线学习 + 3σ 异常检测 + 持久化 |
| **总计** | **135** | |

---

## test_jailbreak_corpus.py — 越狱语料库回归 (5 tests)

35 条样本，5 个类别：`role_switch` (13), `delimiter` (4), `encoded` (4), `unicode` (4), `structural` (7)

每个条目标注 `expected_t0_block` / `expected_t2_block`，自动验证防御层行为。新增攻击向量只需加一条 JSON。

## test_key_auth.py — 认证与权限 (17 tests)

- KeyStore: 生成格式、SHA256 确定性、创建/验证/吊销/列出、持久化、多 key 独立
- 角色阈值: admin+2, operator±0, viewer-999（钳制到 0）
- 权限验证: viewer 写操作被 veto、viewer 只读操作放行、admin 高阈值免确认

## test_semantic_ambiguity.py — 语义歧义 (7 tests)

25 条中文歧义语料：含"清理"但疑问的、明确指令的、观察陈述的。

确认旧 Router 的关键词误判（"帮我看看需不需要清理" → action），同时验证 T0/T2 不误杀合法输入。

## test_baseline.py — 审计基线 (9 tests)

日画像计算、3σ 异常检测、无异常日、持久化往返、画像上限、sigma 符号验证。

## test_confirm_audit_api.py — 确认流程 (9 tests)

确认拒绝/未找到/批准执行、按用户过滤、TTL 过期、审计轨迹查询/未找到/验证今日/验证指定日期。全部带 Bearer 认证。

## 覆盖矩阵

| 层级 | 快乐路径 | 悲观路径 | 并发 | 角色 | 歧义 |
|------|:--------:|:--------:|:----:|:----:|:----:|
| T0 注入检测 | 5 | 4 | 1 | — | 25 |
| T1 风险评分 | 3 | 2 | — | — | — |
| T2 约束引擎 | 4 | 3 | — | 5 | — |
| T3 沙箱 | 2 | 5 | — | — | — |
| 姿态引擎 | 8 | 4 | — | — | — |
| 流水线/审计 | 11 | — | — | — | — |
| 认证/权限 | 17 | — | — | — | — |
| 基线/异常 | 9 | — | — | — | — |
| 会话 | 10 | — | 1 | — | — |

---

## 运行方式

```bash
cd backend
python -m pytest tests/ -v
```
