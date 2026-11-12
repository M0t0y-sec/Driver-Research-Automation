# DRA 新机器交接说明

给你（接手的 AI）的完整上下文。读完这份文档你应当能独立继续开发，不需要回看历史对话。

---

## 1. 项目是什么

DRA（Driver Research Automation）是一个 Windows 内核驱动漏洞研究平台。使用者通过它分析 `.sys` 驱动、提出安全假设、在隔离虚拟机里构造 PoC 验证、抓取崩溃栈并产出可提交给厂商的漏洞报告。

真实目标是产出赏金级别的漏洞报告。判别标准只有一条：**能不能在没有人工补刀的情况下，走完「驱动 → 真实 IOCTL → PoC → 崩溃栈 → root cause」这条链**。

仓库：`https://github.com/M0t0y-sec/Driver-Research-Automation`
当前提交：`1ea3c7d`（最新，含本文档前一次推送）

---

## 2. 技术栈与运行方式

| 项 | 值 |
|---|---|
| Python | 3.13（`pyproject.toml` 未锁版本，用机器自带的即可） |
| 后端 | FastAPI + LangGraph + Pydantic v2，位于 `server/`，包名 `dra` |
| 前端 | Vite + React 18 + TypeScript，位于 `web/` |
| 存储 | 本地 JSON + 文件系统（`artifacts/`），Postgres/S3 接口已预留 |

启动后端：

```bash
cd server
python -m pip install -e ".[dev]"
python -m uvicorn dra.main:app --host 127.0.0.1 --port 8000
```

启动前端：

```bash
cd web
pnpm install
pnpm dev          # http://127.0.0.1:5173，/api 已代理到 8000
```

跑测试：

```bash
cd server
python -m pytest -q
```

**当前基线：132 passed。任何低于这个数字的改动都视为回归。**

---

## 3. 现在能做什么（已实测验证）

### 3.1 静态分析：真实可用

`server/dra/tools/tools/analyze_pe.py` 与 `ioctl_extract.py` 基于 pefile + capstone，能从真实驱动里提取事实。实测结果：

| 驱动 | 提取结果 | 外部核对 |
|---|---|---|
| `beep.sys` | IOCTL `0x00010000`，handler RVA `0x1010`，设备 `\Device\Beep` | 与公开的 `IOCTL_BEEP_SET` 完全一致 |
| `mouclass.sys` | `0xb0268` 等 3 个 code | 解出 `CTL_CODE(0x0B, 0x9A, METHOD_BUFFERED, FILE_ANY_ACCESS)`，与键鼠类驱动一致 |
| `null.sys` / `npfs.sys` | `no_device_control_handler` | 诚实报「没有」，不编造 |

`attack_surface_extract` 对无法判定的可达性返回 `"unknown"`，并在 `reachability_detail.basis` 里写明判定依据不足的原因。

### 3.2 QA 闸门：能拒绝假结论

证据分 `EvidenceKind = surface | sink | control_flow | crash | root_cause | impact`，只从结构化字段推导。`DEFECT_KINDS = {sink, control_flow, crash}`。

只有攻击面级证据（IOCTL 常量存在、设备名可见）时，finding 最高只能到 `NEEDS_HUMAN`，拿不到 `qa_pass`。

实测：对 `beep.sys` 跑完整研究图，得到 4 条真实观察（IOCTL `0x00010000`、`rva=0x1010`、`\Device\Beep`、`IoCreateDevice`），最终产出 0 条假设、0 条 finding。这些观察只证明攻击面存在，没有指向具体缺陷，因此不构成结论。

### 3.3 假设生成：要求可证伪

`agents/hypothesis.py` 允许并鼓励返回 `{"hypotheses": [], "reasoning": "..."}`。每条假设必须带具体 `falsification` 判据并引用本轮真实存在的 observation id，否则丢弃并记入 `hypothesis_rejected`。

### 3.4 PoC 生成：可编译源码

`tools/tools/poc_generate.py` 从 IOCTL 事实生成 C 代码，覆盖 `METHOD_BUFFERED` / `IN_DIRECT` / `OUT_DIRECT` / `NEITHER`，内置 `argv` 长度变异便于 fuzz，附 `cl` 与 `clang-cl` 编译命令。

### 3.5 Lab 与崩溃分析

- `server/dra/lab/`：VirtualBox provider（调 `VBoxManage`）、Health Check、实验指纹
- `server/dra/triage/`：解析 `!analyze -v`，产出 root cause / impact / exploitability，能区分驱动自身缺陷与第三方模块

### 3.6 LLM

`server/dra/llm/anthropic_client.py` 按 task tier 路由模型，无密钥时自动降级到 mock 并打告警。**真实 API 路径至今只跑过假传输测试，从未实弹验证。**

---

## 4. 现在还不能做什么

1. **从未在真实 VM 里跑过一次完整实验。** 动态验证链路（PoC 编译 → 部署 → 执行 → 抓 dump → 分析）一行都没实弹跑过。
2. **没有真实 LLM 密钥**，推理质量未验证。
3. **没有已知有漏洞的测试样本**，无法验证「能挖到洞」。
4. 前端浏览器端到端联调做得有限。

---

## 5. 你的机器上要完成的任务

你有一台新建的 VirtualBox Windows 11 虚拟机。按下面顺序推进，每步都必须验证通过再进下一步。

### 任务 1：环境准备

```bash
git clone https://github.com/M0t0y-sec/Driver-Research-Automation
cd Driver-Research-Automation/server
python -m pip install -e ".[dev]"
python -m pytest -q          # 必须 132 passed
```

依赖 `pefile` 与 `capstone` 已写入 `pyproject.toml`，正常安装即可。

### 任务 2：安装内核调试器

```powershell
winget install Microsoft.WinDbg
```

装完确认 `kd.exe` 可被找到。Health Check 会在 `PATH`、`DRA_KD_PATH`、Windows Kits 默认目录中查找。

### 任务 3：给 VM 配置内核调试通道

VM 必须处于关机状态。

```bash
VBoxManage modifyvm "<你的VM名>" --uart1 0x3F8 4 --uartmode1 server "\\.\pipe\kd_dra"
```

在 guest 内（管理员 CMD）：

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

**Windows 11 特有坑，必须处理**：默认开启的「内存完整性 / HVCI」与 Secure Boot 会阻止测试签名驱动加载。需要：

- 关闭「内核隔离 → 内存完整性」，重启
- 关闭 Secure Boot，或在 VBox 设置中禁用
- 关闭 Windows Defender 的实时防护（否则编译出的 PoC 可能被拦截）

做完后重启 guest，用 `bcdedit /enum {current}` 确认 `testsigning Yes`、`debug Yes`。

### 任务 4：让 Health Check 全绿

```bash
cd server
export DRA_LAB_PROVIDER=virtualbox
export DRA_LAB_VM="<你的VM名>"
export DRA_LAB_SNAPSHOT="<你打算做基线快照的名字>"
python -c "
from dra.lab.factory import get_lab_provider
from dra.lab.health import HealthCheck
import dataclasses, json
rep = HealthCheck(get_lab_provider(), vm='<你的VM名>').run()
print(json.dumps(dataclasses.asdict(rep), indent=2, ensure_ascii=False))
"
```

逐项修到全部 `pass`。Health Check 对每个失败项都给出了可直接执行的修复命令。

### 任务 5：造一个「已知有漏洞」的测试驱动

**这是当前最关键的一步**，也是唯一能证明整条链路有效的方式。

写一个最小的 Windows 内核驱动，故意留一个可被普通用户触发的缺陷。建议实现 `METHOD_BUFFERED` 的 IOCTL，在 handler 里对用户输入长度不做校验就 `RtlCopyMemory` 到固定大小栈缓冲区。用测试证书签名，装进 VM。

要求：
- 有明确的 `IoCreateDevice` + `IoCreateSymbolicLink`，设备名形如 `\Device\DraTest`
- 至少一个 IOCTL，能被非管理员进程打开并发送
- 缺陷必须是确定可触发的（固定长度溢出即可）

这个驱动只用于验证平台，不用于提交任何漏洞报告。

### 任务 6：端到端验证

用上面这个测试驱动跑完整链路：

1. `ioctl_extract` 能提取出真实 IOCTL code 与 handler RVA
2. `poc_generate` 生成的 C 代码能编译
3. PoC 在 VM 里执行后触发 BSOD
4. 抓到 dump，`kd.exe` 能分析出崩溃栈
5. `triage` 模块能把 `!analyze -v` 输出解析成 root cause，并正确归因到你的测试驱动而非第三方模块
6. QA 闸门在拿到崩溃证据后能把 finding 推进到 `qa_pass`

任何一步断裂，修哪里就改哪里。**这一步跑通之前，不要开始找真实驱动的漏洞。**

### 任务 7：接真实 LLM

拿到 Anthropic API key 后写入 `server/.env`：

```
DRA_LLM_PROVIDER=anthropic
DRA_ANTHROPIC_API_KEY=sk-ant-...
```

然后：

```bash
python scripts/smoke_live_llm.py
```

确认推理输出质量。重点是验证：面对只有攻击面证据的驱动，模型是否会正确返回零假设。

### 任务 8：开始真实研究

链路验证通过后，才是找真实驱动漏洞。优先关注这几类高赏金模式：

- `METHOD_NEITHER` + 直接解引用用户指针
- 缺少 `ProbeForRead` / `ProbeForWrite`
- 输入长度未校验导致的内核池溢出
- size 计算整数溢出
- 设备 ACL 允许普通用户打开 + 危险 IOCTL

---

## 6. 必须遵守的约束

### 6.1 项目规则

仓库根目录有 `AGENTS.md`，每次会话自动加载。核心几条：

- 中文回复，直接陈述
- 禁止「不是……而是……」句式
- Python 不写无必要的 `from __future__`、不写宽泛的 `try/except Exception`、不留死代码
- 文档只描述「现在是什么」

交付前按 `AGENTS.md` 第 4 节自查。

### 6.2 证据纪律

这个平台存在的意义是压制模型幻觉，不要把它做成反过来。

- 不许为了让测试通过而伪造 observation、evidence 或 crash
- 拿不到的事实写 `null` 或 `"unknown"`，不猜
- `qa_pass` 必须由真实缺陷证据支撑，攻击面存在本身不算
- 崩溃不等于漏洞，必须经过 root cause 与可利用性评估

### 6.3 合规

只在你自己搭建的隔离 VM 里对你自己可控的驱动做实验。装在物理机上的生产驱动、第三方系统、未授权目标，一律不碰。

发现的真实漏洞走厂商披露流程，报告里不要附可直接复用的武器化利用代码。

---

## 7. 目录速查

```
server/dra/
├── agents/          11 个 Agent 节点
├── api/             FastAPI 路由
├── evidence/        证据强度与 kind 推导
├── graph/           LangGraph 状态机
├── lab/             VirtualBox provider / Health Check / 指纹
├── llm/             Anthropic client + mock + 路由
├── models/          Pydantic 数据模型
├── prompts/         提示词模板
├── qa/              QA 闸门规则
├── storage/         本地 JSON 存储
├── tools/           Tool Gateway + 具体工具
└── triage/          WinDbg 解析 / 缺陷分类 / 可利用性
```

---

## 8. 建议的第一条命令

```bash
cd server && python -m pytest -q
```

先确认 132 passed，再动任何代码。
