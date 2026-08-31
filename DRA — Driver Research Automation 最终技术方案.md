# DRA — Driver Research Automation
## AI 驱动的 Windows 驱动安全研究与检测评估平台

---

# 1. 项目定位

DRA（Driver Research Automation）是一套基于 **LangGraph + 多 Agent + Windows 隔离实验室 + 安全分析工具链 + Evidence 证据系统** 构建的 AI 安全研究平台。

核心目标不是让一个 LLM “自己乱跑”，而是建立一个可：

- 自动分析
- 自动提出研究假设
- 自动规划实验
- 自动执行受控验证
- 自动采集证据
- 自动分析 Crash / Trace / Telemetry
- 自动评估安全产品检测覆盖
- 自动生成 Finding
- 可暂停
- 可恢复
- 可回滚
- 可审计
- 可人工介入

的完整研究闭环。

核心思想：

> **LangGraph 管研究流程，Agent 管推理，Tool Gateway 管工具，Windows Lab 管实验，Evidence Store 管事实。**

---

# 2. 总体目标

输入：

```text
driver.sys
```

经过：

```text
样本
 ↓
Recon
 ↓
Static Analysis
 ↓
Reverse Engineering
 ↓
Attack Surface Modeling
 ↓
Hypothesis Generation
 ↓
Hypothesis Ranking
 ↓
Experiment Planning
 ↓
Controlled Validation
 ↓
Crash / Trace / Telemetry
 ↓
Triage
 ↓
Evidence
 ↓
QA
 ↓
Finding
 ↓
Detection Evaluation
```

最终输出：

```text
Driver Profile
Attack Surface
Hypotheses
Experiments
Validation Results
Crashes
Evidence
Findings
Detection Evaluation
Research Report
```

---

# 3. 总体架构

```text
                         ┌─────────────────────┐
                         │       Web UI        │
                         │ Project / Task      │
                         │ Experiment / Report │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │       FastAPI       │
                         └──────────┬──────────┘
                                    │
                                    ▼
              ┌─────────────────────────────────────────┐
              │             LangGraph Runtime            │
              │                                         │
              │ State / Routing / Checkpoint            │
              │ Retry / Resume / Interrupt / HITL       │
              └──────────────────────┬──────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
          ▼                          ▼                          ▼
   Research Agents             Experiment Agents         QA Agents
          │                          │                          │
          └──────────────────────────┼──────────────────────────┘
                                     │
                                     ▼
                           ┌────────────────────┐
                           │   Tool Gateway     │
                           └─────────┬──────────┘
                                     │
             ┌───────────────────────┼────────────────────────┐
             ▼                       ▼                        ▼
       Static / RE Tools       Build / Debug Tools       VM / Lab Tools
             │                       │                        │
             └───────────────────────┼────────────────────────┘
                                     ▼
                           ┌────────────────────┐
                           │   Windows Lab      │
                           │ VM / Snapshot      │
                           │ Telemetry          │
                           └─────────┬──────────┘
                                     │
                                     ▼
                           ┌────────────────────┐
                           │ Evidence Layer     │
                           │ PostgreSQL / MinIO │
                           └────────────────────┘
```

---

# 4. 为什么选择 LangGraph

LangGraph 作为整个系统的 **Orchestration Backbone**。

原因不是因为它“会 Agent”，而是因为 DRA 本质上是：

> **一个长期运行、有状态、可循环、可恢复、需要人工介入的研究工作流。**

典型情况：

```text
Research Run
 ↓
Static Analysis
 ↓
Hypothesis
 ↓
Experiment
 ↓
VM Crash
 ↓
Checkpoint
 ↓
恢复
 ↓
重新实验
```

因此需要：

- State
- Graph
- Conditional Edge
- Checkpoint
- Persistence
- Retry
- Resume
- Interrupt
- Human-in-the-loop

LangGraph 官方当前定位正是面向 long-running、stateful Agent workflow，并提供 persistence、durable execution、interrupt/HITL 等能力。

---

# 5. 不采用“超级 Agent”架构

不采用：

```text
Super Agent
   ↓
自己分析
   ↓
自己逆向
   ↓
自己实验
   ↓
自己判断
```

而采用：

```text
Planner
   ↓
Recon
   ↓
RE
   ↓
Hypothesis
   ↓
Experiment Planner
   ↓
Validation
   ↓
Triage
   ↓
Evidence
   ↓
Detection Evaluation
   ↓
QA
```

每个 Agent 职责单一。

---

# 6. 最终 Agent 阵容

最终规划为 **10 个核心 Agent**：

```text
01 Planner Agent
02 Recon Agent
03 Reverse Engineering Agent
04 Hypothesis Agent
05 Experiment Planner Agent
06 Validation Agent
07 Triage Agent
08 Telemetry Agent
09 Detection Evaluation Agent
10 QA / Evidence Agent
```

其中 Evidence 可以内部进一步拆成独立 Evidence Agent，但第一版可以和 QA 合并。

---

# 7. Agent 01 — Planner Agent

### 目标

负责研究任务总体规划。

### 输入

```text
Target
Project Configuration
Research Policy
Environment
Budget
```

### 输出

```text
ResearchPlan
```

例如：

```text
Phase 1
 └─ Recon

Phase 2
 └─ Static Analysis

Phase 3
 └─ Attack Surface

Phase 4
 └─ Hypothesis

Phase 5
 └─ Validation

Phase 6
 └─ Evidence / QA
```

### 原则

Planner 负责：

> “下一步研究什么？”

不负责直接执行工具。

---

# 8. Agent 02 — Recon Agent

### 目标

建立驱动基础信息。

负责：

- PE metadata
- 架构
- Sections
- Imports
- Exports
- Strings
- Dependencies
- Driver metadata
- Interface inventory
- IOCTL inventory
- 其他可观察的攻击面信息

输出：

```python
ReconResult
```

核心原则：

> **工具负责发现事实，LLM 负责解释事实。**

不能把模型猜测当成事实。

---

# 9. Agent 03 — Reverse Engineering Agent

### 目标

进行代码与数据流层面的安全研究。

关注：

- 函数关系
- Call Graph
- 输入来源
- 数据流
- 权限边界
- 内存操作
- 参数验证
- 状态转换
- 用户态 / 内核态边界
- 关键路径

输出：

```text
Function Findings
Dataflow Findings
Potential Weaknesses
```

注意：

```text
Observation
≠
Hypothesis
```

---

# 10. Agent 04 — Hypothesis Agent

### 目标

从分析结果中生成：

> **值得验证的研究假设。**

例如：

```text
HYP-001
HYP-002
HYP-003
...
```

每个 Hypothesis 包含：

```text
id
category
location
source
sink
description
evidence_ids
confidence
priority
validation_required
```

优先级可以综合：

```text
Priority =
Impact
× Confidence
× Reachability
× Testability
```

目的：

> 不要把所有候选问题无脑拿去实验。

---

# 11. Agent 05 — Experiment Planner Agent

这是一个独立 Agent。

Hypothesis Agent 回答：

> “哪里可能有问题？”

Experiment Planner 回答：

> “如何设计一个实验验证这个假设？”

输出：

```text
ExperimentPlan
```

包括：

```text
hypothesis
prerequisites
environment
setup
observation points
success criteria
failure criteria
rollback requirement
```

它负责设计实验，不负责最终判定漏洞。

---

# 12. Agent 06 — Validation Agent

这是**漏洞验证 Agent**。

它负责：

```text
Hypothesis
 ↓
Experiment Plan
 ↓
Prepare Lab
 ↓
Build Test Artifact
 ↓
Run Controlled Experiment
 ↓
Collect Result
```

结果可能是：

```text
CONFIRMED
REJECTED
INCONCLUSIVE
```

### 关键原则

Validation Agent：

- 不直接操作宿主机
- 不直接执行任意 Shell
- 不直接拥有无限权限
- 不直接接触生产环境

必须：

```text
Validation Agent
      ↓
Tool Gateway
      ↓
Lab Controller
      ↓
Isolated Windows VM
```

---

# 13. Agent 07 — Triage Agent

专门处理实验结果。

输入：

```text
Crash
BSOD
Exception
Hang
Trace
Logs
Dump
Execution Metadata
```

输出：

```text
reproducible
related_to_hypothesis
confidence
severity
classification
```

特别重要：

> **Crash ≠ Vulnerability。**

必须证明：

```text
Crash
 ↓
与 Hypothesis 相关
 ↓
可重复
 ↓
证据充分
 ↓
Finding
```

---

# 14. Agent 08 — Telemetry Agent

这个 Agent 是后面检测评估的重要基础。

负责收集、整理实验产生的行为：

```text
Process Events
Image Load
Driver Events
File Events
Registry Events
Network Events
ETW
Event Logs
Security Product Telemetry
```

输出：

```text
Behavior Profile
Telemetry Timeline
Event Correlation
```

它只回答：

> **“实验过程中发生了什么？”**

---

# 15. Agent 09 — Detection Evaluation Agent

这是原先讨论的“致盲 / 免杀”位置。

但最终定义调整为：

# Detection Evaluation Agent

职责：

> **评估安全产品对实验行为的可见性、检测覆盖和检测缺口。**

流程：

```text
Confirmed Finding
       ↓
Controlled Experiment
       ↓
Telemetry
       ↓
Security Product Result
       ↓
Detection Correlation
       ↓
Coverage Analysis
       ↓
Detection Gap
```

输出：

```text
DetectionResult
```

例如：

```text
detected:
    true / false / partial / inconclusive

detection_stage:
    ...

observed_telemetry:
    ...

behavior_coverage:
    ...

detection_confidence:
    ...

detection_gap:
    ...
```

---

# 16. “致盲 / 免杀”的最终定位

不设计成：

```text
自动生成绕过 EDR 的代码
自动生成免杀 Payload
自动修改样本规避现实产品
```

而设计成：

```text
Baseline Behavior
       ↓
Controlled Variant
       ↓
Telemetry
       ↓
Detection Result
       ↓
Coverage Comparison
       ↓
Robustness Evaluation
```

研究的是：

> **安全产品在哪些受控行为变化下检测能力下降。**

例如：

```text
Baseline Coverage   91%
Variant A           88%
Variant B           63%
Variant C           90%
```

最终结论：

```text
Detection Robustness:
HIGH / MEDIUM / LOW

Weak Dimension:
Behavior Correlation

Evidence:
EVD-001
EVD-007
EVD-013
```

这样可以研究检测系统的盲区和鲁棒性，而不是把 Agent 变成现实环境的自动免杀器。

---

# 17. Agent 10 — QA Agent

QA 是整个系统的“反方”。

它不相信其他 Agent 的结论。

例如发现：

```text
“安全产品没有检测到”
```

QA 必须检查：

```text
Telemetry 是否正常？
安全产品策略是否启用？
事件是否丢失？
检测是否存在延迟？
测试环境是否正确？
结果是否可重复？
```

最终：

```text
CONFIRMED
PARTIAL
NOT_OBSERVED
INCONCLUSIVE
```

这一步非常重要，可以显著降低：

> LLM 把实验配置问题误判成安全产品检测缺失。

---

# 18. 最终 LangGraph

```text
START
  │
  ▼
Load Project
  │
  ▼
Planner
  │
  ▼
Recon
  │
  ▼
Static / Reverse Analysis
  │
  ▼
Attack Surface
  │
  ▼
Hypothesis Generation
  │
  ▼
Hypothesis Ranking
  │
  ▼
Experiment Planner
  │
  ▼
Validation
  │
  ▼
Triage
  │
  ├───────────────┐
  │               │
REJECTED       CONFIRMED
  │               │
  ▼               ▼
Archive      Evidence
                  │
                  ▼
              Telemetry
                  │
                  ▼
         Detection Evaluation
                  │
                  ▼
                  QA
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
        PASS    RETRY    REJECT
          │       │        │
          ▼       │        ▼
       Finding    │      Archive
                  │
                  └──> Experiment Planner
```

---

# 19. ResearchState

所有 Agent 不通过自然语言互相传递大段内容。

统一使用：

```python
class ResearchState(TypedDict):
    project_id: str
    task_id: str

    target: TargetInfo
    environment: EnvironmentInfo

    static_analysis: StaticAnalysisResult
    attack_surface: AttackSurface

    hypotheses: list[Hypothesis]
    selected_hypothesis: str | None

    experiments: list[Experiment]
    executions: list[Execution]

    crashes: list[Crash]
    traces: list[Trace]

    telemetry: list[TelemetryEvent]
    evidence: list[Evidence]
    findings: list[Finding]

    current_phase: str
    current_node: str

    retry_count: int
    budget: Budget

    confidence: float
    status: str

    errors: list[ErrorRecord]
```

---

# 20. Structured Output

所有 Agent 必须使用：

```text
Pydantic
+
JSON Schema
+
Structured Output
```

例如：

```python
class Hypothesis(BaseModel):
    id: str
    category: str
    location: str

    source: str | None
    sink: str | None

    description: str

    evidence_ids: list[str]

    confidence: float
    priority: float

    validation_required: bool
```

原则：

> **Agent 之间传结构化对象，不传“聊天记录”。**

---

# 21. Tool Gateway

这是系统最关键的基础设施之一。

统一：

```text
Agent
 ↓
Tool Gateway
 ↓
Policy Check
 ↓
Tool
 ↓
Artifact
 ↓
Tool Result
```

工具分类：

```text
Static / PE
Reverse Engineering
Build
Debugger
VM
Experiment
Telemetry
Artifact
```

例如：

```text
analyze_pe
run_static_analysis
query_symbol
get_callgraph

compile_project
build_test_artifact

create_vm
start_vm
stop_vm
create_snapshot
revert_snapshot

run_lab_job
collect_logs
collect_dump
collect_trace
```

---

# 22. Tool API

统一请求：

```json
{
  "request_id": "...",
  "tool": "analyze_pe",
  "project_id": "...",
  "target_id": "...",
  "parameters": {},
  "policy_context": {}
}
```

统一响应：

```json
{
  "request_id": "...",
  "status": "success",
  "result": {},
  "artifacts": [],
  "logs": [],
  "duration_ms": 1234
}
```

这样以后更换 Ghidra、IDA、WinDbg、不同 VM 平台都不会影响 Agent。

---

# 23. Windows Lab

必须独立于 Agent Runtime。

架构：

```text
AI Server
    │
    ▼
Lab Controller
    │
    ├── VM Pool A
    ├── VM Pool B
    └── VM Pool C
```

每个 VM：

```text
Windows
 ├── Driver
 ├── Test Harness
 ├── Debugging
 ├── Monitoring
 └── Telemetry
```

---

# 24. 实验生命周期

每个 Experiment：

```text
Clean Snapshot
      ↓
Prepare
      ↓
Deploy
      ↓
Execute
      ↓
Collect Evidence
      ↓
Triage
      ↓
Revert
```

绝对不要让一次实验污染下一次实验。

目标：

> **每一个实验都可重复。**

---

# 25. Lab 网络

默认：

```text
Isolated Network
```

原则：

- 实验 VM 与宿主机隔离
- 默认不访问公网
- 控制面单独通信
- 必要通信使用 allowlist
- 记录实验网络行为
- 实验结束恢复干净快照

---

# 26. Policy Engine

所有高风险 Tool 必须经过 Policy。

例如：

```yaml
tool: run_lab_job
environment: isolated_lab
allowed: true
```

不同操作：

```text
LOW
MEDIUM
HIGH
```

分别对应：

```text
LOW
→ 自动

MEDIUM
→ Policy Check

HIGH
→ Human Approval
```

---

# 27. Human-in-the-loop

第一版就必须设计。

流程：

```text
Agent
 ↓
Tool Request
 ↓
Policy
 ↓
Needs Approval
 ↓
Interrupt
 ↓
Human
 ↓
Approve / Reject
 ↓
Resume
```

LangGraph 的 checkpoint + interrupt 模型正好适合这里。

---

# 28. Evidence System

所有研究对象拥有唯一 ID：

```text
DRV-001
HYP-017
EXP-032
RUN-044
CRASH-008
EVD-119
FND-007
```

形成完整 Research Lineage：

```text
DRV-001
  ↓
HYP-017
  ↓
EXP-032
  ↓
RUN-044
  ↓
CRASH-008
  ↓
EVD-119
  ↓
FND-007
```

以后审一个 Finding，可以一路追溯到：

```text
原始驱动
 ↓
具体分析
 ↓
具体假设
 ↓
具体实验
 ↓
具体结果
 ↓
具体证据
```

---

# 29. Observation / Hypothesis / Finding 三层分离

这是整个项目必须坚持的规则。

```text
Observation
    ↓
Hypothesis
    ↓
Validation
    ↓
Finding
```

不能：

```text
LLM Observation
    ↓
直接 Finding
```

例如：

```text
Observation:
某函数存在特定输入路径

Hypothesis:
该路径可能存在安全问题

Validation:
实验结果支持该假设

Finding:
经过证据和 QA 后确认
```

---

# 30. 数据库

推荐：

```text
PostgreSQL
```

核心表：

```text
projects
targets
analyses
hypotheses
experiments
executions
crashes
telemetry
evidence
findings
agent_runs
tool_runs
approvals
```

---

# 31. Artifact Storage

大型文件不进入 PostgreSQL。

使用：

```text
MinIO / S3
```

保存：

```text
drivers
dumps
traces
logs
reports
binaries
analysis artifacts
```

PostgreSQL 只保存：

```text
artifact_id
sha256
location
size
metadata
```

---

# 32. Vector Database

Vector DB 只做语义检索：

```text
历史 Finding
历史研究
类似函数
类似调用路径
历史实验
安全知识
```

不要把 Vector DB 当事实数据库。

事实：

```text
PostgreSQL
```

原始 Artifact：

```text
MinIO
```

语义检索：

```text
Vector DB
```

三者职责分离。

---

# 33. Model Router

不要一个模型包打天下。

```text
             Model Router
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
     Small       Mid       Large
```

Small：

```text
分类
提取
标签
JSON 修复
```

Mid：

```text
代码解释
候选分析
实验结果分析
```

Large：

```text
复杂 RE
跨函数推理
研究规划
QA
```

---

# 34. Context Builder

不能每次把整个 ResearchState 塞给模型。

应该：

```text
Global State
     ↓
Context Builder
     ↓
Agent-specific Context
```

例如 Reverse Agent 只拿：

```text
Relevant Functions
Call Graph
Dataflow
Imports
Prior Evidence
```

而不是整个项目。

---

# 35. Observability

记录：

```text
Graph Run
Node
Agent
LLM
Tool
Experiment
VM
Telemetry
Evidence
```

最终能够回答：

```text
这个 Finding 是谁发现的？

用了什么模型？

调用了哪些工具？

执行了几次实验？

哪个实验成功？

哪个 Agent 判断错了？

用了多少 Token？

耗时多久？
```

---

# 36. 项目目录

```text
dra/
│
├── apps/
│   ├── api/
│   ├── worker/
│   └── web/
│
├── graph/
│   ├── graph.py
│   ├── state.py
│   ├── nodes.py
│   ├── edges.py
│   ├── interrupts.py
│   └── checkpointer.py
│
├── agents/
│   ├── planner.py
│   ├── recon.py
│   ├── reverse.py
│   ├── hypothesis.py
│   ├── experiment.py
│   ├── validation.py
│   ├── triage.py
│   ├── telemetry.py
│   ├── detection.py
│   └── qa.py
│
├── tools/
│   ├── base.py
│   ├── pe/
│   ├── reverse/
│   ├── debugger/
│   ├── build/
│   ├── vm/
│   └── telemetry/
│
├── lab/
│   ├── controller.py
│   ├── provider.py
│   ├── snapshots.py
│   └── policies.py
│
├── models/
│   ├── target.py
│   ├── hypothesis.py
│   ├── experiment.py
│   ├── evidence.py
│   └── finding.py
│
├── storage/
│   ├── postgres/
│   ├── artifacts/
│   └── vector/
│
├── policies/
│   └── default.yaml
│
├── prompts/
│
└── tests/
```

---

# 37. API

第一版：

```text
POST /projects
GET  /projects/{id}

POST /targets
GET  /targets/{id}

POST /research/start
GET  /research/{id}

POST /research/{id}/resume
POST /research/{id}/approve
POST /research/{id}/reject

GET /hypotheses
GET /experiments
GET /findings
GET /evidence
```

---

# 38. Web UI

第一版只需要：

### Project

```text
Projects
Targets
Runs
Findings
```

### Research Run

```text
Current Phase
Current Node
Progress
Agent Trace
```

### Hypothesis

```text
ID
Priority
Confidence
Evidence
Status
```

### Experiment

```text
Plan
Environment
Execution
Result
Artifacts
```

### Finding

```text
Summary
Evidence
Reproduction Status
Confidence
Timeline
```

---

# 39. 技术栈

第一版建议：

```text
Python
FastAPI
LangGraph
Pydantic
PostgreSQL
Redis
MinIO
Docker
OpenTelemetry
```

Windows Lab：

```text
Windows VM
Ghidra / IDA
WinDbg
MSVC / LLVM
```

具体分析工具通过 Tool Gateway 接入。

---

# 40. OpenAI Agents SDK 的位置

第一版：

> **不引入。**

采用：

```text
LangGraph
+
Pydantic
+
自己的 Agent Wrapper
```

以后某个模块确实需要：

```text
复杂 handoff
独立 Agent Runtime
专用 sandbox agent
```

再考虑 OpenAI Agents SDK。

目前 Agents SDK 已经提供 agents、handoffs、guardrails、sessions、HITL、tracing 等能力，因此可以作为后期扩展，而不是第一版的必要依赖。

---

# 41. MCP 的位置

第一版：

> **不强制使用 MCP。**

直接：

```text
Tool Gateway
```

后期可以把：

```text
RE Tools
VM Tools
Artifact Tools
Telemetry Tools
```

逐步 MCP 化。

原则：

> 技术服务于架构，不为了“用了 MCP”而用 MCP。

---

# 42. 五阶段开发计划

## Phase 0：基础设施

目标：

```text
FastAPI
LangGraph
PostgreSQL
Redis
MinIO
Logging
Checkpoint
```

验收：

```text
创建 Task
 ↓
运行 Graph
 ↓
保存 State
 ↓
Checkpoint
 ↓
Resume
```

---

## Phase 1：Static Research MVP

流程：

```text
driver.sys
 ↓
Recon
 ↓
Static Analysis
 ↓
Reverse
 ↓
Hypothesis
 ↓
Ranking
 ↓
Evidence
 ↓
Report
```

这一阶段不做自动实验。

目标：

> 先证明 Agent 能够稳定地产出结构化研究假设。

---

## Phase 2：Windows Lab

加入：

```text
VM Controller
Snapshot
Build
Debugger
Telemetry
```

形成：

```text
Hypothesis
 ↓
Experiment
 ↓
VM
 ↓
Result
```

---

## Phase 3：自动验证循环

加入：

```text
Hypothesis Queue
 ↓
Experiment Planner
 ↓
Validation
 ↓
Triage
 ↓
Evidence
 ↓
QA
 ↓
Next Hypothesis
```

形成真正的 Research Loop。

---

## Phase 4：Detection Evaluation

加入：

```text
Telemetry
 ↓
Detection Evaluation
 ↓
Coverage
 ↓
Gap Analysis
 ↓
QA
```

研究安全产品：

- 可见性
- 检测覆盖
- 行为关联
- 检测鲁棒性
- 检测缺口

而不是自动生成现实环境免杀/绕过方案。

---

## Phase 5：Research Platform

加入：

```text
Web UI
Multi-user
Project Management
Experiment History
Finding Database
Agent Tracing
Evaluation
Benchmark
```

最终成为完整平台。

---

# 43. MVP 的严格范围

第一版只要求：

```text
输入 driver.sys
       ↓
PE Analysis
       ↓
Recon
       ↓
Static Analysis
       ↓
Reverse
       ↓
Attack Surface
       ↓
Hypothesis
       ↓
Ranking
       ↓
Evidence
       ↓
Report
```

必须做到：

1. 自动建立 Driver Profile
2. 自动提取攻击面
3. 自动产生结构化 Hypothesis
4. 每个 Hypothesis 有 Evidence
5. 每个 Hypothesis 有 Confidence
6. 每个 Hypothesis 有 Priority
7. Graph 支持 Pause
8. Graph 支持 Resume
9. Graph 支持 Retry
10. 所有 Agent Run 可追踪

---

# 44. 第二阶段验收

增加：

```text
Hypothesis
 ↓
Experiment Planner
 ↓
Lab
 ↓
Execution
 ↓
Result
```

要求：

- VM 可创建
- Snapshot 可创建
- Snapshot 可恢复
- Experiment 可记录
- Artifact 可归档
- Execution 可追溯

---

# 45. 第三阶段验收

系统能够：

```text
自动选择 Hypothesis
 ↓
设计实验
 ↓
执行实验
 ↓
读取结果
 ↓
判断结果
 ↓
重新规划
```

也就是：

> **真正形成闭环。**

---

# 46. 第四阶段验收

系统能够：

```text
实验行为
 ↓
Telemetry
 ↓
Detection
 ↓
Coverage
 ↓
Gap Analysis
```

并能够区分：

```text
DETECTED
PARTIAL
NOT_OBSERVED
INCONCLUSIVE
```

---

# 47. 最终评估指标

不要只看：

> “AI 找到了几个漏洞。”

需要建立 Benchmark。

指标：

```text
Hypothesis Precision
Hypothesis Recall
False Positive Rate
Validation Success Rate
Reproduction Rate
Average Experiments / Finding
Time To Finding
Evidence Quality
Agent Error Rate
Token Cost
Infrastructure Cost
```

最终可以回答：

> AI 是否真的比人工更高效？

---

# 48. 三条核心工程原则

## 原则一：事实和推测分离

```text
Observation
 ↓
Hypothesis
 ↓
Validation
 ↓
Finding
```

---

## 原则二：LLM 和执行环境分离

```text
LLM
 ↓
Tool Gateway
 ↓
Policy
 ↓
Sandbox
```

不允许：

```text
LLM
 ↓
Host Shell
```

---

## 原则三：每个实验必须可重复

记录：

```text
Target
Environment
Snapshot
Input
Tool Version
Model Version
Experiment
Result
Artifact
Evidence
```

这样所有 Finding 都可以追溯。

---

# 49. 最终完整版架构

```text
                         ┌──────────────────────┐
                         │       Web UI         │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       FastAPI        │
                         └──────────┬───────────┘
                                    │
                                    ▼
              ╔══════════════════════════════════════════╗
              ║              LangGraph                   ║
              ║                                          ║
              ║ Planner                                  ║
              ║   ↓                                      ║
              ║ Recon                                    ║
              ║   ↓                                      ║
              ║ Reverse                                  ║
              ║   ↓                                      ║
              ║ Hypothesis                               ║
              ║   ↓                                      ║
              ║ Experiment Planner                       ║
              ║   ↓                                      ║
              ║ Validation                               ║
              ║   ↓                                      ║
              ║ Triage                                   ║
              ║   ↓                                      ║
              ║ Evidence                                 ║
              ║   ↓                                      ║
              ║ Telemetry                                ║
              ║   ↓                                      ║
              ║ Detection Evaluation                     ║
              ║   ↓                                      ║
              ║ QA                                       ║
              ║                                          ║
              ║ Checkpoint / Resume / Retry / HITL      ║
              ╚══════════════════╤═══════════════════════╝
                                 │
                                 ▼
                       ┌───────────────────┐
                       │   Tool Gateway    │
                       └─────────┬─────────┘
                                 │
          ┌──────────────────────┼───────────────────────┐
          ▼                      ▼                       ▼
     Static / RE           Build / Debug            VM / Lab
          │                      │                       │
          └──────────────────────┼───────────────────────┘
                                 ▼
                       ┌───────────────────┐
                       │  Windows Lab      │
                       │  VM Pool          │
                       │  Snapshot         │
                       │  Telemetry        │
                       └─────────┬─────────┘
                                 │
                                 ▼
                 ┌────────────────────────────────┐
                 │       Evidence Layer            │
                 │                                │
                 │ PostgreSQL │ MinIO │ Vector DB │
                 └────────────────┬───────────────┘
                                  │
                                  ▼
                            ┌────────────┐
                            │  Finding   │
                            └────────────┘
```

---

# 50. 最终 Agent 职责表

| Agent | 核心问题 | 是否执行实验 |
|---|---|---:|
| Planner | 下一步研究什么？ | ❌ |
| Recon | 驱动有什么？ | ❌ |
| Reverse | 哪些地方值得关注？ | ❌ |
| Hypothesis | 哪里可能存在安全问题？ | ❌ |
| Experiment Planner | 怎么验证假设？ | ❌ |
| Validation | 在隔离环境执行验证 | ✅ |
| Triage | 实验结果说明什么？ | ❌ |
| Telemetry | 实验过程中发生了什么？ | ❌ |
| Detection Evaluation | 安全产品看到了什么？ | ❌ |
| QA | 这个结论可信吗？ | ❌ |

其中：

> **漏洞验证 = Validation Agent + Triage Agent**

而：

> **致盲/免杀研究 = Detection Evaluation Agent + Telemetry Agent + QA Agent**

最终不把它设计成自动化现实环境绕过系统，而是设计成**受控检测鲁棒性评估系统**。

---

# 51. 最终技术路线结论

整个项目最终应该形成：

> **一个以 LangGraph 为核心编排层、以多 Agent 为研究决策层、以 Tool Gateway 为执行抽象层、以 Windows VM Lab 为实验层、以 Evidence Store 为事实层的 AI 驱动安全研究平台。**

最重要的不是：

```text
“Agent 有多聪明”
```

而是：

```text
Agent
 ↓
提出假设
 ↓
设计实验
 ↓
执行实验
 ↓
获得事实
 ↓
更新状态
 ↓
重新决策
```

即：

# Observe → Understand → Hypothesize → Experiment → Observe → Evaluate → Update

这才是 DRA 最核心的 Research Loop。

---

# 52. 最终推荐的第一开发顺序

不要同时开十条线。

严格按：

```text
① ResearchState
        ↓
② LangGraph 主 Graph
        ↓
③ 3 个 Agent
   Planner / Recon / Hypothesis
        ↓
④ Tool Gateway
        ↓
⑤ Evidence System
        ↓
⑥ Reverse Agent
        ↓
⑦ Windows Lab
        ↓
⑧ Experiment Planner
        ↓
⑨ Validation + Triage
        ↓
⑩ Telemetry + Detection Evaluation
        ↓
⑪ QA
        ↓
⑫ Web UI / Benchmark
```

其中 **①～⑤ 是第一版地基**。

如果地基没问题，后面的 Agent 基本都是往里面“插模块”。

---

# 53. 最终一句话定义 DRA

> **DRA 不是一个会“自动黑进驱动”的 Agent，而是一个能够自主提出安全研究假设、在隔离环境中设计和执行可重复实验、根据实验事实不断修正判断，并最终形成可审计安全结论的 AI Security Research Engine。**

这个定位我认为是我们前面所有讨论里最成熟、也最值得真正落地的版本。