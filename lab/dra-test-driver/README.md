# DraTestDriver

用于验证 DRA 研究链路的靶子驱动。缺陷是预先设计好的，每次崩溃都能确切归因，因此可以判断链路上哪一环断了。

只用于你自己搭建的隔离虚拟机。不要装在任何你在意的机器上，也不要拿它当漏洞样本上报。

## IOCTL 一览

设备路径：`\\.\DraTest`

| IOCTL | 方法 | 缺陷 | 预期 bugcheck |
|---|---|---|---|
| `0x222000` | METHOD_BUFFERED | 输入长度未校验，直接 `RtlCopyMemory` 进 64 字节栈缓冲区 | `0x7F` / `0x1A` / `0x50` |
| `0x222007` | METHOD_NEITHER | 把用户指针当 `UNICODE_STRING` 用，不做 `ProbeForRead` | `0xA` / `0x50` |
| `0x222008` | METHOD_BUFFERED | 无缺陷，直接返回成功 | 无（阴性对照） |

`0x222008` 是阴性对照。平台上不该为它产出任何 finding。

## 编译（宿主机）

前置：Visual Studio 2022 的「使用 C++ 的桌面开发」工作负载，加 Windows 11 WDK。

管理员 PowerShell：

```powershell
cd lab\dra-test-driver
.\build.ps1
```

产物：

```
bin\x64\Release\DraTestDriver.sys   驱动
DraTestDriver.cer                   测试证书公钥，需要拷进 guest
```

`build.ps1` 会自签测试证书并签名。如果项目文件报错，可用备选路径：在 VS 里新建「Kernel Mode Driver, Empty (WDM)」项目，把 `DraTestDriver.c` 加进去编译，再手动 `signtool sign`。

## 安装（guest 内）

先确认 guest 已开启测试签名并重启：

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

Windows 11 还必须：

- 关闭「核心隔离 → 内存完整性」（HVCI）
- 关闭 Secure Boot
- 关闭 Defender 实时防护，否则编译出的 PoC 可能被拦截

把 `.sys` 和 `.cer` 拷进 guest，管理员 PowerShell：

```powershell
.\install.ps1 -Action install -CertPath .\DraTestDriver.cer -SysPath .\DraTestDriver.sys
```

看到 `Driver loaded` 后，`\\.\DraTest` 即可访问。

卸载：

```powershell
.\install.ps1 -Action remove
```

## 用 DRA 验证链路

### 第一步：静态分析应提取出真实 IOCTL

```python
from dra.tools.tools.ioctl_extract import ioctl_extract
ioctl_extract(r"C:\path\to\DraTestDriver.sys")
```

期望：`device_control_handler_rva` 非空，`ioctl_codes` 中包含 `0x222000`、`0x222007`、`0x222008`。

### 第二步：生成 PoC

栈溢出用例：

```python
from dra.tools.tools.poc_generate import poc_generate
poc_generate(device_name=r"\Device\DraTest", ioctl_code=0x222000, input_length=4096)
```

指针解引用用例，`UNICODE_STRING` 的 `Buffer` 指向 `0x1`：

```python
from dra.tools.tools.poc_generate import poc_generate
template = bytes.fromhex("02000200000000000100000000000000")
poc_generate(device_name=r"\Device\DraTest", ioctl_code=0x222007, input_template=template)
```

### 第三步：编译并执行

把生成的 `.c` 拷进 guest，按源码头部的命令编译，然后运行。

生成器默认的 `run_prerequisites` 里会给出运行前提。

### 第四步：抓崩溃

宿主机另开终端，连上内核调试管道：

```cmd
kd.exe -k com:pipe,port=\\.\pipe\kd_dra,resets=0,reconnect
```

guest 崩溃后执行：

```
!analyze -v
```

把输出保存为文本。

### 第五步：喂给 triage

```python
from dra.triage import parse_windbg_analysis, classify_defect

text = open("analyze.txt", encoding="utf-8").read()
analysis = parse_windbg_analysis(text)
print(analysis.bugcheck_code, analysis.module_name, analysis.stack[:3])

result = classify_defect(analysis, target_module="DraTestDriver")
print(result.category, result.attribution)
```

期望：`module_name` 为 `DraTestDriver`，`category` 是栈溢出或非法内存访问，`attribution` 归到本驱动而非第三方模块。

### 第六步：确认阴性对照

对 `0x222008` 跑一遍，平台不应产出任何 finding。

## 清理

验证完成后从 guest 卸载驱动，删除测试证书：

```powershell
.\install.ps1 -Action remove
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq 'CN=DraTestDriverTest' } | Remove-Item
Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -eq 'CN=DraTestDriverTest' } | Remove-Item
```
