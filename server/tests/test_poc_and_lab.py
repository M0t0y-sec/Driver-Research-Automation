"""Tests for PoC generation and the real VirtualBox lab layer.

Everything here is hermetic: VBoxManage is replaced by a fake runner that
records argv and returns canned ``--machinereadable`` output, so the suite
never starts, stops or modifies the real win10_rev VM (or any other VM).
"""

import hashlib
import json
import subprocess

import pytest
from fastapi.testclient import TestClient

from dra.config import SETTINGS
from dra.lab import (
    HealthCheck,
    KdLocator,
    LabCommandError,
    LabUnavailableError,
    VMNotFoundError,
    VirtualBoxProvider,
    experiment_fingerprint,
    parse_machinereadable,
    parse_vm_list,
    resolve_vboxmanage,
)
from dra.main import app
from dra.tools.tools import mock_lab
from dra.tools.tools.poc_generate import decode_ctl_code, poc_generate

VM_UUID = "{11111111-2222-3333-4444-555555555555}"

# VirtualBox 7.2 plain `list vms` format (--machinereadable is rejected).
LIST_VMS = (
    f'"win10_rev" {{{VM_UUID.strip("{}")}}}\n'
    '"win 10 test" {22222222-3333-4444-5555-666666666666}\n'
)
LIST_RUNNING = '"win 10 test" {22222222-3333-4444-5555-666666666666}\n'

SHOWVMINFO = f'''name="win10_rev"
groups="/"
ostype="Windows10_64"
UUID="{VM_UUID}"
CfgFile="C:\\\\Users\\\\researcher\\\\VirtualBox VMs\\\\win10_rev\\\\win10_rev.vbox"
VMState="poweroff"
VMStateChangeTime="2026-11-11T00:00:00.000000000"
uart1="0x03f8,4"
uartmode1="server,\\\\.\\pipe\\kd_win10_rev"
SnapshotName="golden"
SnapshotUUID="{{aaaaaaaa-1111-2222-3333-444444444444}}"
SnapshotName-1="clean"
SnapshotUUID-1="{{bbbbbbbb-1111-2222-3333-444444444444}}"
'''

SHOWVMINFO_RUNNING = SHOWVMINFO.replace('VMState="poweroff"', 'VMState="running"')


# ---------------------------------------------------------------------------
# Fake VBoxManage
# ---------------------------------------------------------------------------

def _ok(text: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout=text, stderr="")


def _fail(stderr: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 1, stdout="", stderr=stderr)


class FakeRunner:
    """Records argv, returns canned CompletedProcess; fails on surprises."""

    def __init__(self, handlers: dict[tuple[str, ...], subprocess.CompletedProcess]):
        self.handlers = handlers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
        key = tuple(argv[1:])
        handler = self.handlers.get(key)
        if handler is None:
            for pattern, value in self.handlers.items():
                if len(pattern) <= len(key) and key[: len(pattern)] == pattern:
                    handler = value
                    break
        if handler is None:
            raise AssertionError(f"unexpected VBoxManage invocation: {argv}")
        return handler

    @property
    def keys(self) -> list[tuple[str, ...]]:
        return [tuple(call[1:]) for call in self.calls]


def _provider(handlers: dict[tuple[str, ...], subprocess.CompletedProcess]):
    fake = FakeRunner(handlers)
    provider = VirtualBoxProvider(
        exe="VBoxManage",
        runner=fake,
        env={},
        which=lambda _name: None,
        exists=lambda _path: False,
    )
    return provider, fake


def _good_health_handlers(info: str = SHOWVMINFO):
    return {
        ("--version",): _ok("7.2.12r165820\n"),
        ("showvminfo", "win10_rev", "--machinereadable"): _ok(info),
    }


def _missing_kd() -> KdLocator:
    return KdLocator(
        env={},
        which=lambda _name: None,
        exists=lambda _path: False,
        glob=lambda _pattern: [],
    )


# ---------------------------------------------------------------------------
# PoC generation: four METHODs
# ---------------------------------------------------------------------------

METHOD_CASES = [
    (0, "METHOD_BUFFERED"),
    (1, "METHOD_IN_DIRECT"),
    (2, "METHOD_OUT_DIRECT"),
    (3, "METHOD_NEITHER"),
]


def _poc(method: int, **overrides) -> dict:
    params = dict(
        ioctl={
            "ctl_code": {
                "device_type": 0x22,
                "function": 0x800,
                "method": method,
                "access": 1,
            }
        },
        device_name=r"\Device\TestDrv",
        input_length=0x20,
        output_length=0x10,
        fill_byte=0x42,
        input_template="41 42 43",
    )
    params.update(overrides)
    return poc_generate(**params)


@pytest.mark.parametrize("method,method_name", METHOD_CASES)
def test_poc_generates_method_specific_code(method, method_name):
    result = _poc(method)
    source = result["source"]

    assert result["method"] == method
    assert result["method_name"] == method_name
    assert result["ctl_code"]["function"] == 0x800
    assert result["ctl_code"]["device_type"] == 0x22
    assert f"CTL_CODE(0x0022, 0x800, {method_name}, FILE_READ_ACCESS)" in source
    assert f"#define IOCTL_CODE      0x0022600{method}u" in source
    assert '#define DEVICE_PATH     L"\\\\\\\\.\\\\TestDrv"' in source
    assert "#define INPUT_LENGTH    32u" in source
    assert "#define OUTPUT_LENGTH   16u" in source
    assert "#define FILL_BYTE       66" in source
    assert "0x41, 0x42, 0x43" in source
    assert "CreateFileW(" in source
    assert "DeviceIoControl(" in source
    assert "GetLastError()" in source
    assert "strtoul(argv[1]" in source
    assert source.lstrip().startswith("/*")
    assert "AUTHORIZED" in source.upper()
    assert "disposable VM" in source

    if method == 0:
        assert "Irp->AssociatedIrp.SystemBuffer" in source
        assert "HeapAlloc" in source
        assert "VirtualAlloc" not in source
    elif method == 1:
        assert "METHOD_IN_DIRECT" in source
        assert "Irp->MdlAddress" in source
        assert "MmGetSystemAddressForMdlSafe" in source
        assert "VirtualAlloc" in source
        assert "HeapAlloc" in source
    elif method == 2:
        assert "METHOD_OUT_DIRECT" in source
        assert "Irp->MdlAddress" in source
        assert "VirtualAlloc" in source
        assert "HeapAlloc" in source
    else:
        assert "Type3InputBuffer" in source
        assert "Irp->UserBuffer" in source
        assert "VirtualAlloc" in source
        assert "HeapAlloc" not in source


@pytest.mark.parametrize(
    "method,marker",
    [
        (0, "both can be ordinary"),
        (1, "OUTPUT buffer is probed and locked as an MDL"),
        (2, "results into the output buffer"),
        (3, "probing, alignment and access checks are entirely"),
    ],
)
def test_poc_documents_method_buffer_semantics(method, marker):
    result = _poc(method)
    assert marker in result["source"]
    semantics = result["buffer_semantics"]
    assert semantics["method"] == method
    assert semantics["method_name"] == METHOD_CASES[method][1]
    assert semantics["input"] and semantics["output"]
    assert semantics["notes"]


def test_poc_compile_commands_and_prerequisites():
    result = _poc(1)
    assert result["compile"]["cl"].startswith("cl ")
    assert result["compile"]["clang_cl"].startswith("clang-cl ")
    assert result["source_filename"] in result["compile"]["cl"]
    assert result["compile"]["cl"].endswith(".exe")
    assert any("testsigning" in step for step in result["run_prerequisites"])
    assert any("sc.exe create" in step for step in result["run_prerequisites"])
    assert any("kd.exe" in step for step in result["run_prerequisites"])


def test_poc_decodes_code_and_validates_conflicting_facts():
    result = poc_generate(ioctl_code=0x00226002, device_name="TestDrv")
    assert result["ctl_code"] == {
        **decode_ctl_code(0x00226002),
        "device_type_hex": "0x0022",
        "function_hex": "0x800",
        "macro": "CTL_CODE(0x0022, 0x800, METHOD_OUT_DIRECT, FILE_READ_ACCESS)",
    }
    assert result["device"]["win32_path"] == r"\\.\TestDrv"

    with pytest.raises(ValueError, match="decodes to device_type"):
        poc_generate(
            ioctl={
                "code": 0x00010000,
                "ctl_code": {
                    "device_type": 2,
                    "function": 0,
                    "method": 0,
                    "access": 0,
                },
            },
            device_name=r"\Device\Beep",
        )
    with pytest.raises(ValueError, match="ioctl code conflict"):
        poc_generate(ioctl={"code": 0x00010000}, ioctl_code=0x00010001,
                     device_name=r"\Device\Beep")
    with pytest.raises(ValueError, match="missing"):
        poc_generate(
            ioctl={"ctl_code": {"device_type": 1, "method": 0}},
            device_name=r"\Device\Beep",
        )


def test_poc_accepts_single_ioctl_codes_entry_but_rejects_ambiguity():
    facts = {
        "device_names": [r"\Device\Beep"],
        "ioctl_codes": [
            {
                "code": 0x00010000,
                "ctl_code": {"device_type": 1, "function": 0, "method": 0,
                             "access": 0},
            }
        ],
    }
    result = poc_generate(ioctl=facts)
    assert result["ioctl_code"] == 0x00010000
    assert result["method_name"] == "METHOD_BUFFERED"
    assert any("single entry" in note for note in result["notes"])

    ambiguous = {
        "device_names": [r"\Device\Beep"],
        "ioctl_codes": [
            {"code": 0x00010000},
            {"code": 0x00010004},
        ],
    }
    with pytest.raises(ValueError, match="2 IOCTL codes"):
        poc_generate(ioctl=ambiguous)


def test_poc_notes_derived_device_path():
    result = poc_generate(ioctl_code=0x00010000, device_name=r"\Device\Beep")
    assert result["device"]["path_source"] == "derived-from-nt-path"
    assert any(
        "DosDevices" in note and "GLOBALROOT" in note for note in result["notes"]
    )


def test_poc_rejects_invalid_parameters():
    with pytest.raises(ValueError, match="method"):
        poc_generate(
            ioctl={"ctl_code": {"device_type": 1, "function": 0, "method": 4,
                                "access": 0}},
            device_name=r"\Device\Beep",
        )
    with pytest.raises(ValueError, match="input_length"):
        poc_generate(ioctl_code=0x00010000, device_name="Beep",
                     input_length=-1)
    with pytest.raises(ValueError, match="fill_byte"):
        poc_generate(ioctl_code=0x00010000, device_name="Beep", fill_byte=0x100)
    with pytest.raises(ValueError, match="even number"):
        poc_generate(ioctl_code=0x00010000, device_name="Beep",
                     input_template="ABC")
    with pytest.raises(ValueError, match="device_name"):
        poc_generate(ioctl_code=0x00010000, device_name="")


def test_poc_uses_device_name_from_ioctl_facts_and_writes_file(tmp_path):
    facts = {
        "code": 0x00010000,
        "ctl_code": {"device_type": 1, "function": 0, "method": 0, "access": 0},
        "device_names": [r"\Device\Beep"],
    }
    result = poc_generate(ioctl=facts, output_dir=str(tmp_path))
    assert result["device"]["input"] == r"\Device\Beep"
    assert result["written"] is True
    written = tmp_path / result["source_filename"]
    assert written.read_text(encoding="utf-8") == result["source"]
    assert result["source_sha256"] == hashlib.sha256(
        result["source"].encode("utf-8")
    ).hexdigest()


def test_poc_tool_is_registered():
    from dra.tools.gateway import get_default_registry

    names = {spec.name for spec in get_default_registry().list()}
    assert "poc_generate" in names
    assert "lab_health_check" in names


# ---------------------------------------------------------------------------
# VirtualBox provider: parsing and explicit errors
# ---------------------------------------------------------------------------

def test_parse_machinereadable_handles_both_forms():
    parsed = parse_machinereadable(
        '"win10_rev"="{uuid}"\n'
        'name="win10_rev"\n'
        'uartmode1="server,\\\\.\\pipe\\kd"\n'
        "free form line without equals\n"
    )
    assert parsed["win10_rev"] == "{uuid}"
    assert parsed["name"] == "win10_rev"
    assert parsed["uartmode1"] == r"server,\\.\pipe\kd"


def test_parse_vm_list_handles_plain_and_machinereadable_forms():
    plain = parse_vm_list(
        f'"win10_rev" {{{VM_UUID.strip("{}")}}}\n'
        '"<inaccessible>" {b37d74e3-d3e4-4844-abea-8cc473028314}\n'
        '"escaped ""quote" {33333333-4444-5555-6666-777777777777}\n'
    )
    assert plain["win10_rev"] == VM_UUID.strip("{}")
    assert plain["<inaccessible>"].startswith("b37d74e3")
    assert 'escaped "quote' in plain
    # Legacy machinereadable form is still accepted.
    assert parse_vm_list('"old"="{uuid}"\n') == {"old": "{uuid}"}


def test_list_vms_parses_real_vbox72_plain_format():
    provider, fake = _provider(
        {
            ("list", "vms"): _ok(LIST_VMS),
            ("list", "runningvms"): _ok(LIST_RUNNING),
        }
    )
    vms = provider.list_vms()
    by_name = {info.name: info for info in vms}
    assert set(by_name) == {"win10_rev", "win 10 test"}
    assert by_name["win10_rev"].uuid == VM_UUID.strip("{}")
    assert by_name["win10_rev"].state is None
    assert by_name["win 10 test"].state == "running"
    assert fake.keys == [("list", "vms"), ("list", "runningvms")]


def test_vm_info_parses_state_snapshots_and_uart():
    provider, _ = _provider(
        {("showvminfo", "win10_rev", "--machinereadable"): _ok(SHOWVMINFO)}
    )
    info = provider.vm_info("win10_rev")
    assert info.name == "win10_rev"
    assert info.uuid == VM_UUID
    assert info.state == "poweroff"
    assert info.ostype == "Windows10_64"
    assert info.snapshots == ("golden", "clean")
    assert info.raw["uartmode1"] == r"server,\\.\pipe\kd_win10_rev"
    assert provider.vm_state("win10_rev") == "poweroff"


def test_find_vm_and_list_snapshots():
    provider, _ = _provider(
        {
            ("list", "vms"): _ok(LIST_VMS),
            ("list", "runningvms"): _ok(LIST_RUNNING),
            ("showvminfo", "win10_rev", "--machinereadable"): _ok(SHOWVMINFO),
        }
    )
    assert provider.find_vm("WIN10_REV").name == "win10_rev"
    assert provider.find_vm(VM_UUID.strip("{}")).name == "win10_rev"
    assert provider.find_vm("not-a-vm") is None

    snapshots = {snap.name: snap.uuid for snap in provider.list_snapshots("win10_rev")}
    assert snapshots == {
        "golden": "{aaaaaaaa-1111-2222-3333-444444444444}",
        "clean": "{bbbbbbbb-1111-2222-3333-444444444444}",
    }


def test_command_failure_carries_vboxmanage_stderr():
    stderr = "VBoxManage.exe: error: The machine 'win10_rev' is not mutable"
    provider, _ = _provider(
        {("startvm", "win10_rev", "--type", "headless"): _fail(stderr)}
    )
    with pytest.raises(LabCommandError) as excinfo:
        provider.start("win10_rev", headless=True)
    assert excinfo.value.stderr == stderr
    assert "not mutable" in str(excinfo.value)
    assert excinfo.value.returncode == 1


def test_unknown_vm_maps_to_vm_not_found():
    stderr = (
        "VBoxManage.exe: error: Could not find a registered machine named "
        "'missing'"
    )
    provider, _ = _provider(
        {("showvminfo", "missing", "--machinereadable"): _fail(stderr)}
    )
    with pytest.raises(VMNotFoundError) as excinfo:
        provider.vm_info("missing")
    assert excinfo.value.vm == "missing"
    assert "Could not find a registered machine" in excinfo.value.stderr
    assert "Could not find a registered machine" in str(excinfo.value)


def test_unavailable_vboxmanage_is_explicit_not_empty():
    resolution = resolve_vboxmanage(
        r"C:\missing\VBoxManage.exe",
        env={},
        which=lambda _name: r"C:\found\VBoxManage.exe",
        exists=lambda path: path == r"C:\found\VBoxManage.exe",
    )
    assert resolution.path is None
    assert resolution.source == "argument"  # explicit config wins, no silent fallback

    provider = VirtualBoxProvider(
        exe=None,
        runner=None,
        env={},
        which=lambda _name: None,
        exists=lambda _path: False,
    )
    assert provider.available is False
    assert "not found" in provider.unavailable_reason
    assert provider.guidance
    with pytest.raises(LabUnavailableError) as excinfo:
        provider.version()
    assert "VBoxManage" in str(excinfo.value)
    assert excinfo.value.guidance


# ---------------------------------------------------------------------------
# VirtualBox provider: command construction (fake runner only)
# ---------------------------------------------------------------------------

def test_mutating_commands_build_expected_argv():
    pipe = r"\\.\pipe\kd_win10_rev"
    provider, fake = _provider(
        {
            ("startvm", "win10_rev", "--type", "headless"): _ok(),
            ("controlvm", "win10_rev", "poweroff"): _ok(),
            ("snapshot", "win10_rev", "restore", "golden"): _ok(),
            ("snapshot", "win10_rev", "take", "new-snap", "--description",
             "from test"): _ok(),
            ("modifyvm", "win10_rev", "--uart1", "0x3F8", "4",
             "--uartmode1", "server", pipe): _ok(),
        }
    )
    provider.start("win10_rev", headless=True)
    provider.stop("win10_rev")
    provider.restore_snapshot("win10_rev", "golden")
    provider.create_snapshot("win10_rev", "new-snap", description="from test")
    provider.set_kernel_debug_serial("win10_rev", pipe)

    assert fake.keys == [
        ("startvm", "win10_rev", "--type", "headless"),
        ("controlvm", "win10_rev", "poweroff"),
        ("snapshot", "win10_rev", "restore", "golden"),
        ("snapshot", "win10_rev", "take", "new-snap", "--description",
         "from test"),
        ("modifyvm", "win10_rev", "--uart1", "0x3F8", "4",
         "--uartmode1", "server", pipe),
    ]


def test_destroy_disposable_powers_off_running_vm_then_deletes_it():
    provider, fake = _provider(
        {
            ("showvminfo", "win10_rev", "--machinereadable"):
                _ok(SHOWVMINFO_RUNNING),
            ("controlvm", "win10_rev", "poweroff"): _ok(),
            ("unregistervm", "win10_rev", "--delete"): _ok(),
        }
    )
    provider.destroy_disposable("win10_rev")
    assert fake.keys == [
        ("showvminfo", "win10_rev", "--machinereadable"),
        ("controlvm", "win10_rev", "poweroff"),
        ("unregistervm", "win10_rev", "--delete"),
    ]


def test_destroy_disposable_skips_poweroff_when_already_off():
    provider, fake = _provider(
        {
            ("showvminfo", "win10_rev", "--machinereadable"): _ok(SHOWVMINFO),
            ("unregistervm", "win10_rev", "--delete"): _ok(),
        }
    )
    provider.destroy_disposable("win10_rev")
    assert fake.keys == [
        ("showvminfo", "win10_rev", "--machinereadable"),
        ("unregistervm", "win10_rev", "--delete"),
    ]


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def test_health_check_passes_with_complete_lab(tmp_path):
    kd = tmp_path / "kd.exe"
    kd.write_bytes(b"fake")
    provider, _ = _provider(_good_health_handlers())
    report = HealthCheck(
        provider,
        vm="win10_rev",
        snapshot="golden",
        kd_locator=KdLocator(explicit=str(kd), env={}),
    ).run()

    assert report.passed is True
    assert report.status == "ok"
    assert set(report.checks) == {
        "vboxmanage",
        "vm_exists",
        "vm_state",
        "snapshot",
        "kernel_debug_serial",
        "kd_exe",
    }
    assert all(check.status == "pass" for check in report.checks.values())
    expected_fp = hashlib.sha256(
        f"win10_rev|{VM_UUID}|Windows10_64".encode("utf-8")
    ).hexdigest()
    assert report.vm_fingerprint == expected_fp
    payload = report.to_dict()
    assert payload["passed"] is True
    assert payload["checks"]["kernel_debug_serial"]["data"]["port"] == 1


def test_health_check_missing_kd_gives_actionable_guidance():
    provider, _ = _provider(_good_health_handlers())
    report = HealthCheck(
        provider,
        vm="win10_rev",
        snapshot="golden",
        kd_locator=_missing_kd(),
    ).run()

    assert report.passed is False
    assert report.checks["kd_exe"].status == "fail"
    assert report.checks["kd_exe"].guidance
    combined = " ".join(report.checks["kd_exe"].guidance)
    assert "Windows SDK" in combined
    assert "Debugging Tools" in combined
    assert "DRA_KD_PATH" in combined
    assert "winget install Microsoft.WinDbg" in combined
    # The failure must also be surfaced at the report level, not swallowed.
    assert any("kd.exe" in failure for failure in report.failures)
    assert any("Windows SDK" in step for step in report.to_dict()["guidance"])


def test_health_check_reports_missing_snapshot_and_serial(tmp_path):
    kd = tmp_path / "kd.exe"
    kd.write_bytes(b"fake")
    no_serial = "\n".join(
        line for line in SHOWVMINFO.splitlines()
        if not line.startswith(("uart1=", "uartmode1="))
    )
    provider, _ = _provider(_good_health_handlers(no_serial))
    report = HealthCheck(
        provider,
        vm="win10_rev",
        snapshot="does-not-exist",
        kd_locator=KdLocator(explicit=str(kd), env={}),
    ).run()

    assert report.passed is False
    assert report.checks["snapshot"].status == "fail"
    assert "golden" in report.checks["snapshot"].detail  # lists available ones
    assert report.checks["kernel_debug_serial"].status == "fail"
    serial_guidance = " ".join(report.checks["kernel_debug_serial"].guidance)
    assert "--uartmode1 server" in serial_guidance
    assert "bcdedit /debug on" in serial_guidance
    assert "kd.exe -k com:pipe" in serial_guidance


def test_health_check_provider_unavailable_fails_without_fabricating(tmp_path):
    provider = VirtualBoxProvider(
        exe=None,
        runner=None,
        env={},
        which=lambda _name: None,
        exists=lambda _path: False,
    )
    report = HealthCheck(
        provider,
        vm="win10_rev",
        snapshot="golden",
        kd_locator=_missing_kd(),
    ).run()

    assert report.passed is False
    assert report.checks["vboxmanage"].status == "fail"
    assert report.checks["vm_exists"].status == "fail"
    assert "not evaluated" in report.checks["vm_exists"].detail
    assert report.vm_fingerprint is None
    assert any("virtualbox.org" in step for step in report.to_dict()["guidance"])


# ---------------------------------------------------------------------------
# Experiment fingerprint
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable_and_sensitive():
    base = dict(
        hypothesis_id="HYP-1",
        plan={"inputs": ["TC-1"], "trial_count": 3},
        target=b"driver-bytes",
        snapshot="golden",
        tool_versions={"vbox": "7.2.12", "kd": "10.0"},
        input_data=b"\x41\x42",
    )
    fingerprint = experiment_fingerprint(**base)
    assert len(fingerprint) == 64
    assert experiment_fingerprint(**base) == fingerprint
    # Plan dict ordering must not matter.
    reordered = dict(base, plan={"trial_count": 3, "inputs": ["TC-1"]})
    assert experiment_fingerprint(**reordered) == fingerprint

    changes = {
        "hypothesis_id": "HYP-2",
        "plan": {"inputs": ["TC-1"], "trial_count": 4},
        "target": b"different-driver",
        "snapshot": "clean",
        "tool_versions": {"vbox": "7.2.13", "kd": "10.0"},
        "input_data": b"\x41\x43",
    }
    for key, value in changes.items():
        assert experiment_fingerprint(**dict(base, **{key: value})) != fingerprint


def test_fingerprint_accepts_path_and_precomputed_hashes(tmp_path):
    driver = tmp_path / "target.sys"
    driver.write_bytes(b"driver-bytes")
    expected = hashlib.sha256(b"driver-bytes").hexdigest()

    by_path = experiment_fingerprint(
        hypothesis_id="HYP-1",
        plan={},
        target=str(driver),
        input_data=b"x",
    )
    by_hash = experiment_fingerprint(
        hypothesis_id="HYP-1",
        plan={},
        target_hash=expected,
        input_hash=hashlib.sha256(b"x").hexdigest(),
    )
    assert by_path == by_hash

    with pytest.raises(FileNotFoundError):
        experiment_fingerprint(
            hypothesis_id="HYP-1", plan={}, target=str(tmp_path / "nope.sys")
        )
    with pytest.raises(ValueError, match="disagree"):
        experiment_fingerprint(
            hypothesis_id="HYP-1",
            plan={},
            target=b"driver-bytes",
            target_hash="0" * 64,
        )
    with pytest.raises(ValueError, match="hypothesis_id"):
        experiment_fingerprint(hypothesis_id="", plan={}, target=b"x")


# ---------------------------------------------------------------------------
# Lab tools: no fabricated success
# ---------------------------------------------------------------------------

def test_lab_tools_report_not_available_instead_of_fake_success(monkeypatch):
    monkeypatch.setattr(SETTINGS, "lab_provider", "mock")
    monkeypatch.setattr(SETTINGS, "lab_vm", None)
    monkeypatch.setattr(SETTINGS, "lab_snapshot", None)

    health = mock_lab.lab_health_check("ENV-MOCK")
    assert health["status"] == "not_available"
    assert health["passed"] is False
    assert health["vm_fingerprint"] is None
    assert health["checks"] == {}
    assert "virtualbox" in " ".join(health["guidance"]).lower()

    snapshot = mock_lab.lab_create_snapshot("ENV-MOCK")
    assert snapshot["status"] == "not_available"
    assert snapshot["snapshot_id"] is None
    assert snapshot["vm_fingerprint"] is None

    execution = mock_lab.lab_execute("ENV-MOCK", {"trial_count": 3})
    assert execution["status"] == "not_available"
    assert execution["outcome"] == "error"
    assert execution["execution_id"] is None
    assert execution["trials_total"] == 3
    assert execution["trials_with_signal"] == 0
    assert execution["error"]["code"] == "lab_provider_not_available"

    dumped = json.dumps([health, snapshot, execution])
    assert "mock-fp" not in dumped
    assert "EXE-MOCK" not in dumped


def test_lab_api_health_and_vms_are_honest_when_unconfigured(monkeypatch):
    monkeypatch.setattr(SETTINGS, "lab_provider", "mock")
    monkeypatch.setattr(SETTINGS, "lab_vm", None)

    client = TestClient(app)
    health = client.get("/lab/health")
    assert health.status_code == 200
    body = health.json()
    assert body["passed"] is False
    assert body["status"] == "not_available"
    assert body["vm_fingerprint"] is None
    assert body["guidance"]

    vms = client.get("/lab/vms")
    assert vms.status_code == 503
    assert vms.json()["detail"]["status"] == "not_available"

    snapshots = client.get("/lab/snapshots")
    assert snapshots.status_code == 503
