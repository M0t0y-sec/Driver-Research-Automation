# DRA 实施计划（基于整合方案 v2）

> 目标：把 "DRA — Driver Research Automation 整合方案 v2.md" 落到本机可运行的代码 + 前端。  
> 当前会话不依赖真实 PostgreSQL/MinIO/Windows Lab，先用内存与本地文件跑通 Phase 0/1，端到端可见。

## 0. 环境现状（已验证）

| 组件 | 状态 | 路径 / 备注 |
|---|---|---|
| Python 3.13.0 | 可用 | `D:/every/python/python313/python.exe` |
| LangGraph | 可用 | 已 import OK，version 不可读（不影响使用） |
| FastAPI 0.124.0 | 可用 |  |
| Pydantic 2.12.5 | 可用 |  |
| Uvicorn | 可用 |  |
| httpx 0.28.1 | 可用 |  |
| **LangChain** | **缺失** | 暂不依赖；使用 LangGraph 自身 + pydantic 即可 |
| SQLAlchemy / Alembic | 缺失 | Phase 0/1 用内存 + JSON 持久化，结构按 SQLAlchemy 风格抽象，后续可平移 |
| psycopg / asyncpg | 缺失 | 同上 |
| redis | 缺失 | Checkpoint 用 MemorySaver，需要持久化时再切 PostgresSaver |
| minio | 缺失 | 阶段 0/1 用本地 `artifacts/` 目录做 artefact 存储，接口按 S3 语义抽象 |
| Node 22.20.0 / npm 10.9.3 / pnpm 11.23.0 | 可用 |  |
| 前端项目 | 已存在 | `E:/agentforctf/Driver Research Automation/web/` （Vite + React 18 + TS + Tailwind + shadcn/ui + Radix + TanStack Query + Zustand + React Flow + Monaco + Recharts） |

**关键决定**：  
- 阶段 0/1 不引入 LangChain、不引入 SQLAlchemy、不引入外部 DB；只依赖 LangGraph + FastAPI + Pydantic + httpx。  
- 持久化全部走本地 `artifacts/` 目录 + JSON 索引文件，但接口设计成后续可平移到 Postgres / S3。  
- Windows Lab 不在本会话实现，仅留接口（LabController / HealthCheck / ExperimentFingerprint）和 mock。  
- 真实 LLM 调用本会话**不接外部 API**——所有 Agent 节点先做"确定性骨架 + 明确 prompt 模板 + 调用点"，由占位 LLM Client 返回结构化 mock 数据，让端到端可以跑通。后续接入真实 LLM 时只需替换一个 `LLMClient.call(...)`。

## 1. 工程目录（最终形态，本期只落粗体部分）

```
E:/agentforctf/Driver Research Automation/
├── docs/
│   ├── DRA — Driver Research Automation 最终技术方案.md        # 原方案
│   ├── DRA方案问题建议.md                                        # 建议
│   └── DRA — Driver Research Automation 整合方案 v2.md          # 已写
├── artifacts/                                                    # 临时输出
│
├── server/                                                       # ★ 本期新建
│   ├── pyproject.toml
│   ├── .env.example
│   ├── README.md
│   ├── dra/
│   │   ├── __init__.py
│   │   ├── main.py                          # FastAPI 入口
│   │   ├── config.py                        # 路径 / 配置
│   │   │
│   │   ├── models/                          # Pydantic v2 数据模型
│   │   │   ├── __init__.py
│   │   │   ├── common.py                    # ID, 状态枚举, EvidenceStrength, FailureClass...
│   │   │   ├── target.py
│   │   │   ├── observation.py
│   │   │   ├── attack_surface.py
│   │   │   ├── hypothesis.py
│   │   │   ├── experiment.py
│   │   │   ├── execution.py
│   │   │   ├── crash.py
│   │   │   ├── telemetry.py
│   │   │   ├── evidence.py                  # 含 E0–E7
│   │   │   ├── root_cause.py
│   │   │   ├── impact.py
│   │   │   ├── exploitability.py
│   │   │   ├── finding.py                   # 漏洞报告字段
│   │   │   ├── approval.py
│   │   │   ├── tool_run.py
│   │   │   ├── agent_run.py
│   │   │   ├── visibility.py
│   │   │   ├── detection.py
│   │   │   ├── robustness.py
│   │   │   └── qa.py
│   │   │
│   │   ├── compliance/                      # 合规 / 授权 / 攻击者模型
│   │   │   ├── __init__.py
│   │   │   ├── authz.py
│   │   │   ├── threat_model.py
│   │   │   └── variant_policy.py
│   │   │
│   │   ├── untrusted/                       # Untrusted Input Wrapper
│   │   │   ├── __init__.py
│   │   │   └── wrapper.py
│   │   │
│   │   ├── storage/                         # 抽象存储
│   │   │   ├── __init__.py
│   │   │   ├── filesystem.py                # 本地 JSON + artefacts 目录
│   │   │   ├── repository.py                # 通用仓储接口
│   │   │   └── artifact_store.py            # 哈希 + 路径
│   │   │
│   │   ├── evidence/                        # Evidence Registrar
│   │   │   ├── __init__.py
│   │   │   ├── registrar.py
│   │   │   └── lineage.py
│   │   │
│   │   ├── qa/                              # QA Auditor
│   │   │   ├── __init__.py
│   │   │   ├── rules.py                     # Rule-based QA
│   │   │   ├── auditor.py
│   │   │   └── prompts.py
│   │   │
│   │   ├── tools/                           # Tool Gateway
│   │   │   ├── __init__.py
│   │   │   ├── gateway.py                   # 异步任务 / 幂等 / 审批 / 审计
│   │   │   ├── policy.py
│   │   │   ├── approval.py
│   │   │   ├── registry.py
│   │   │   ├── artifact.py
│   │   │   ├── audit.py
│   │   │   └── tools/
│   │   │       ├── analyze_pe.py            # pefile 解析（无 pefile 时退化）
│   │   │       ├── static_strings.py
│   │   │       ├── attack_surface_extract.py
│   │   │       └── mock_lab.py              # 占位 Lab 控制器
│   │   │
│   │   ├── llm/                             # LLM Client 抽象
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── mock.py                      # 确定性占位，返回结构化 mock
│   │   │   └── router.py                    # Small/Mid/Large + temperature
│   │   │
│   │   ├── agents/                          # 11 个 Agent
│   │   │   ├── __init__.py
│   │   │   ├── planner.py
│   │   │   ├── recon.py
│   │   │   ├── reverse.py                   # 阶段 1 仅辅助型 Summary
│   │   │   ├── hypothesis.py
│   │   │   ├── input_generation.py
│   │   │   ├── experiment.py
│   │   │   ├── validation.py
│   │   │   ├── triage.py                    # Root Cause / Impact / Exploitability
│   │   │   ├── telemetry.py
│   │   │   ├── detection.py                 # Visibility / Detection / Robustness
│   │   │   ├── evidence_registrar.py
│   │   │   └── qa_auditor.py
│   │   │
│   │   ├── graph/                           # LangGraph 多子图
│   │   │   ├── __init__.py
│   │   │   ├── state.py                     # 引用型 ResearchState
│   │   │   ├── checkpointer.py
│   │   │   ├── context.py                   # Context Builder
│   │   │   ├── subgraphs/
│   │   │   │   ├── project.py
│   │   │   │   ├── research.py              # ★ 阶段 1 主图
│   │   │   │   ├── experiment.py            # 留接口
│   │   │   │   ├── detection.py             # 留接口
│   │   │   │   └── qa.py                    # ★ 阶段 1
│   │   │   └── main_graph.py                # 顶层 GraphBuilder
│   │   │
│   │   └── api/                             # FastAPI 路由
│   │       ├── __init__.py
│   │       ├── projects.py
│   │       ├── targets.py
│   │       ├── research.py
│   │       ├── hypotheses.py
│   │       ├── experiments.py
│   │       ├── findings.py
│   │       ├── evidence.py
│   │       ├── lineage.py
│   │       ├── approvals.py
│   │       ├── tool_runs.py
│   │       ├── lab.py
│   │       ├── visibility.py
│   │       ├── detection.py
│   │       ├── robustness.py
│   │       ├── replay.py
│   │       ├── dashboard.py
│   │       └── health.py
│   │
│   └── tests/                               # ★ 阶段 0/1 落 smoke
│       ├── test_state.py
│       ├── test_tool_gateway.py
│       ├── test_evidence_registrar.py
│       ├── test_qa_auditor.py
│       ├── test_research_graph.py
│       └── test_api.py
│
├── web/                                     # 既有 Vite + React 项目
│   └── src/                                 # 本期按整合方案改造
│
└── .hermes/plans/                           # 计划文档（已写）
    └── dra-implementation.md                # 本文件
```

## 2. 阶段目标（本会话范围）

### Phase 0：基础设施（必须完成）

- 引用型 `ResearchState`（`TypedDict`，只存 ID + 摘要 + 路由字段）；
- LangGraph `MemorySaver` Checkpointer；
- 11 个 Agent 的占位骨架（每个一个文件 + 明确接口签名）；
- Tool Gateway 异步壳（`request_id / idempotency_key / status / audit_log / artifact_hash`）；
- Compliance / Authz 框架（每个 Project 必带 `authorized_use`，HIGH 风险工具走 Approval Center）；
- Untrusted Input Wrapper；
- Evidence Registrar（写入 + 哈希 + 血缘 + 强度等级 E0–E7）；
- QA Auditor（Rule-based + Evidence + LLM 三段，阶段 1 主要用前两段）；
- FastAPI 启动 + health 接口。

### Phase 1：Static Research MVP（必须完成）

- 端到端流程：
  ```
  driver.sys (上传)
    → Ingest / Hash / Compliance Check
    → Recon (PE 解析，阶段 1 用纯 Python 解析 + 占位，必要时降级到 read + 简单特征)
    → Attack Surface Extraction
    → Observation Store
    → Hypothesis Generation
    → Hypothesis Ranking (score breakdown)
    → Evidence Registrar (E1 / E3)
    → QA Auditor (rule + evidence)
    → Report
  ```
- 不做：完整 Ghidra/IDA 自动逆、Windows Lab、Validation、Detection。  
- 关键验收：创建 Project → 上传 driver → 启动 Research → 走到 Hypothesis → 给出结构化 Report，每步可见、可暂停、可恢复。

### 前端改造（与整合方案一致）

- 整合方案 §3 总体架构 + §21 Web UI 全部页面：
  - Project / Target / Research Run / Hypothesis / Experiment / Finding
  - Evidence Graph / Lineage / Evidence Chain
  - Approval Center / QA Center
  - Detection Matrix / Replay Panel
  - Dashboard
- API 调用全部对接到 FastAPI（阶段 0/1 未实现的端点返回明确 `501 Not Implemented in Phase X`，不让前端静默失败）。
- 视觉与现有 `index.css` 一致（dark、工业风、JetBrains Mono + Inter + Noto Sans SC）。
- `vite.config.ts` 加 `/api` 代理到 `http://127.0.0.1:8000`。

## 3. 关键架构约束（不妥协）

1. **ResearchState 不存大对象**。所有实体（Observation / Hypothesis / Experiment / Evidence / Finding）只放 ID，实体本身走 `Storage` 仓储。
2. **Agent 之间不传自然语言**，全部 Pydantic v2 结构化。
3. **Tool 调用必须经过 Tool Gateway**，不绕过。
4. **HIGH 风险操作必须走 Approval**。阶段 0/1 不自动执行 HIGH 风险。
5. **Tool 输出进入 LLM 前必须 Untrusted Wrapper**。阶段 0/1 走 mock 也要过 wrapper，保证后续接真实 LLM 时不会破。
6. **QA 不调用 Evidence 写入接口**。两个类分离，调用关系单向。
7. **Crash ≠ Finding**。阶段 1 没有 Crash，但 Finding 仍要走完整 pipeline。
8. **每条 Finding 必须挂 lineage**（即使为空也要记录 lineage_ids）。
9. **资源治理**：阶段 0 至少实现 `retry_count` / `failure_class`，防止无限重试。

## 4. 任务拆分（按顺序）

### 4.1 后端骨架
- [ ] 4.1.1 `pyproject.toml` / `.env.example` / `README.md`
- [ ] 4.1.2 `dra/config.py` + `dra/main.py`（FastAPI app + CORS + lifespan）
- [ ] 4.1.3 `dra/models/common.py`（IDGenerator / 枚举 / 时间戳 / EvidenceStrength / FailureClass / 状态机）
- [ ] 4.1.4 其余 `dra/models/*`（每个一个文件，先列字段，留接口）
- [ ] 4.1.5 `dra/storage/filesystem.py`（JSON + artefacts 目录抽象）+ `repository.py`（通用仓储接口）+ `artifact_store.py`（sha256 + 路径）
- [ ] 4.1.6 `dra/compliance/*`（authz + threat_model + variant_policy）
- [ ] 4.1.7 `dra/untrusted/wrapper.py`（`<UNTRUSTED_DATA>` 包装 + length filter + schema 校验）

### 4.2 Tool Gateway
- [ ] 4.2.1 `gateway.py`：异步任务管理 + 状态机（queued/running/succeeded/failed/timeout/cancelled/needs_approval/blocked_by_policy）
- [ ] 4.2.2 `policy.py`：风险等级 + 工具级策略
- [ ] 4.2.3 `approval.py`：审批接口
- [ ] 4.2.4 `audit.py`：审计日志（每条 tool_run 都留痕）
- [ ] 4.2.5 `registry.py`：工具注册表
- [ ] 4.2.6 工具实现：`analyze_pe` / `static_strings` / `attack_surface_extract` / `mock_lab`

### 4.3 LLM 层
- [ ] 4.3.1 `llm/base.py`（抽象接口：complete / structured / with_schema）
- [ ] 4.3.2 `llm/mock.py`（确定性 mock，按 task_type 返回合理结构）
- [ ] 4.3.3 `llm/router.py`（按 task 路由 + temperature + model tier）

### 4.4 Evidence + QA
- [ ] 4.4.1 `evidence/registrar.py`：写入 / 哈希 / 血缘 / 等级计算
- [ ] 4.4.2 `evidence/lineage.py`：链式追溯
- [ ] 4.4.3 `qa/rules.py`：rule-based 检查（哈希、版本、lineage、schema、状态机）
- [ ] 4.4.4 `qa/auditor.py`：调度 rule + evidence + llm
- [ ] 4.4.5 `qa/prompts.py`：LLM QA prompt 模板

### 4.5 Agent 骨架
- [ ] 4.5.1 11 个 Agent 每个一个文件 + 公共接口（`async def run(state, ctx) -> PartialState`）
- [ ] 4.5.2 每个 Agent 内部走：`ContextBuilder → LLMClient → Schema validate → 写入 Storage → 返回 ID`

### 4.6 LangGraph
- [ ] 4.6.1 `graph/state.py`：引用型 `ResearchState`
- [ ] 4.6.2 `graph/checkpointer.py`：`MemorySaver` 封装
- [ ] 4.6.3 `graph/context.py`：ContextBuilder（按 Agent 角色选字段）
- [ ] 4.6.4 `graph/subgraphs/research.py`：阶段 1 主图（planner → recon → static_summary → attack_surface → hypothesis → hypothesis_ranking → evidence_registrar → qa_auditor → report）
- [ ] 4.6.5 `graph/subgraphs/qa.py`：独立 QA 子图
- [ ] 4.6.6 `graph/main_graph.py`：顶层 GraphBuilder（阶段 1 直接挂 research sub graph）

### 4.7 FastAPI
- [ ] 4.7.1 `/health`、`/dashboard`
- [ ] 4.7.2 `/projects`、`/targets`
- [ ] 4.7.3 `/research/start`、`/research/{id}`、`/research/{id}/pause`、`/research/{id}/resume`、`/research/{id}/cancel`
- [ ] 4.7.4 `/hypotheses`、`/experiments`、`/findings`、`/evidence`
- [ ] 4.7.5 `/projects/{id}/lineage`、`/findings/{id}/evidence-chain`、`/findings/{id}/replay-bundle`
- [ ] 4.7.6 `/approvals`、`/approvals/pending`
- [ ] 4.7.7 `/tool-runs/{id}`、`/lab/health`、`/lab/snapshots`
- [ ] 4.7.8 阶段 1 不实现的端点返回 501

### 4.8 Smoke 测试
- [ ] 4.8.1 `tests/test_state.py`：ResearchState 引用型
- [ ] 4.8.2 `tests/test_tool_gateway.py`：idempotency / status / audit
- [ ] 4.8.3 `tests/test_evidence_registrar.py`：哈希 / 等级 / lineage
- [ ] 4.8.4 `tests/test_qa_auditor.py`：rule-based
- [ ] 4.8.5 `tests/test_research_graph.py`：从 project → report 端到端
- [ ] 4.8.6 `tests/test_api.py`：FastAPI 路由 smoke

### 4.9 前端改造
- [ ] 4.9.1 `vite.config.ts` 加 `/api` 代理
- [ ] 4.9.2 `src/api/client.ts` + `src/api/*`（axios/fetch 封装 + 类型）
- [ ] 4.9.3 `src/types/index.ts` 与后端 Pydantic 对齐
- [ ] 4.9.4 路由（`router.tsx`）覆盖整合方案所有页面
- [ ] 4.9.5 通用组件：`Layout` / `Header` / `Sidebar` / `StatusBadge` / `IdPill` / `EvidenceStrength` / `FailureClassBadge`
- [ ] 4.9.6 页面：
  - Dashboard
  - Project List / Project Detail
  - Target List / Target Detail
  - Research Run Detail（Phase 进度 + Agent Trace + 实时日志）
  - Hypothesis List / Hypothesis Detail（score breakdown）
  - Experiment List / Experiment Detail
  - Finding List / Finding Detail（含 root_cause / impact / exploitability / limitations / CVSS）
  - Evidence Chain（可视化）
  - Lineage（整条链路可视化，可选 React Flow）
  - Approval Center
  - QA Center
  - Detection Matrix（占位）
  - Replay Panel（占位）
  - Lab（占位）
  - Agents（占位）
  - Tools（占位）
  - Settings
- [ ] 4.9.7 状态管理：Zustand stores（`notificationStore` / `uiStore` / 新增 `researchRunStore` 缓存当前 run 状态）

### 4.10 联调
- [ ] 4.10.1 后端 `uvicorn dra.main:app --reload --port 8000`
- [ ] 4.10.2 前端 `pnpm dev`（默认 5173）
- [ ] 4.10.3 浏览器走通：Create Project → Upload driver.sys → Start Research → 观察 Research Run → 看到 Hypothesis 列表 → 看到 Report
- [ ] 4.10.4 跑 `pytest`，全部通过

## 5. 不做（明确）

- 不接真实 LLM（阶段 0/1 用 mock client）
- 不接真实 PostgreSQL / Redis / MinIO（用本地 JSON + artefacts 目录）
- 不接 Windows Lab / VM / Ghidra / WinDbg（mock_lab 返回受控结果）
- 不接真实 pefile（pefile 不在 3.13 环境里，阶段 1 退化为 read + 简单识别 + 字符串 + 长度熵 + 头部判断）
- 不做 Reverse Agent 完整版（仅辅助型 Summary）
- 不做 Detection Evaluation 完整版（Detection Matrix UI 占位 + 接口 501）
- 不做 Replay 实际执行（接口 501 + UI 占位）
- 不做 OpenAI Agents SDK / MCP（明确不引入）
- 不做 i18n（保留中英混排，但不做语言切换）

## 6. 风险与对策

| 风险 | 对策 |
|---|---|
| LangGraph 在 Python 3.13 上偶有兼容问题 | 用官方推荐用法（`from langgraph.graph import StateGraph`），避免弃用 API |
| 真实 driver.sys 二进制复杂，analyze_pe 退化为弱版 | 工具内部允许"弱输出"（只给 hash / size / section 数 / 字符串数），Observation 标记 confidence=low，不阻塞后续 |
| 前端 mock 数据与真实后端契约不齐 | 后端先建，类型生成或手抄对齐；前端调用真实接口失败时显示降级提示而非崩溃 |
| 多文件写入并发 | 阶段 0/1 用单进程 + 同步仓储接口，避免引入 async 复杂度 |
| UI 包络 vs 旧 mock 冲突 | `web/src/mock/` 保留仅做类型参考，运行时数据从 API 拉，移除直接 import mock 数据的页面 |

## 7. 验收（DoD）

完成后必须满足：

1. `python -m pytest server/tests` 全绿。
2. `uvicorn dra.main:app` 启动后 `GET /health` 返回 200 + 包含 `langgraph_version`。
3. `POST /projects` 创建 → `POST /targets` 上传 driver.sys → `POST /research/start` 启动 → 轮询 `GET /research/{id}` 能看到 `phase` 从 `recon` 走到 `report`，最终 `status=completed`。
4. `GET /projects/{id}/lineage` 返回 Research Lineage 链路（即使只有一条），且每个节点带 hash + evidence_strength。
5. `GET /findings/{id}/evidence-chain` 返回 Finding 的证据链。
6. 前端 `pnpm dev` 启动 → 在浏览器能完成上述端到端流程，UI 与整合方案 §3 架构一致，所有页面可路由。
7. 任意 Tool 输出进 LLM 前都有 untrusted wrapper（日志或代码可验证）。
8. QA Auditor 至少跑通 1 条 rule-based 检查（例如 "Finding 必须有 evidence_ids"）。
9. 真实 LLM / 真实 DB / 真实 Lab 在代码中是接口占位（`MockLLMClient` / `FileSystemStore` / `MockLab`），替换为真实实现只需要改一处注入。
