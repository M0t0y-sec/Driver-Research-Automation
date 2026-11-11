"""Generate a compilable Windows IOCTL PoC from static-analysis facts.

Input is a real ``ioctl_extract`` fact (IOCTL code plus its CTL_CODE
fields) and a device name.  Output is:

* complete C source: ``CreateFileW`` -> ``DeviceIoControl`` -> print
  ``GetLastError`` and a hexdump of the buffers;
* the exact ``cl`` / ``clang-cl`` compile commands;
* run prerequisites (test signing, driver load, symbolic link, kernel
  debugging) and the per-METHOD buffer semantics.

The generator only writes source text.  It never compiles, loads a
driver, or talks to a VM.  Buffer length, fill byte and an optional input
template are parameters, so a caller can turn length variation into a
minimal fuzzing loop.

METHOD handling (the reason this generator exists):
  * METHOD_BUFFERED (0)  -- one system buffer, input copied in, output
    copied back; both user buffers are ordinary heap memory.
  * METHOD_IN_DIRECT (1) -- input is a system-buffer copy; the output
    buffer is probed/locked as an MDL.
  * METHOD_OUT_DIRECT (2) -- input is a system-buffer copy; the output
    buffer is an MDL the driver writes into.
  * METHOD_NEITHER (3)  -- no buffering: the driver receives raw
    user-mode pointers and owns probing/alignment.
"""

import hashlib
import re
from pathlib import Path
from string import Template

from ..registry import tool
from ...models.common import RiskLevel

METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

METHOD_NAMES = {
    METHOD_BUFFERED: "METHOD_BUFFERED",
    METHOD_IN_DIRECT: "METHOD_IN_DIRECT",
    METHOD_OUT_DIRECT: "METHOD_OUT_DIRECT",
    METHOD_NEITHER: "METHOD_NEITHER",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
}

AUTHORIZATION_NOTICE = (
    "Generated for authorized local driver research only. Run it in a "
    "disposable VM or against a snapshot you can discard, on a driver you "
    "own or are explicitly authorized to test. Do not run it on a "
    "production machine or against a third-party system."
)


# ---------------------------------------------------------------------------
# CTL_CODE handling
# ---------------------------------------------------------------------------

def decode_ctl_code(code: int) -> dict:
    """Decode an IOCTL value using the CTL_CODE bit layout."""
    method = code & 0x3
    return {
        "device_type": (code >> 16) & 0xFFFF,
        "function": (code >> 2) & 0xFFF,
        "method": method,
        "method_name": METHOD_NAMES[method],
        "access": (code >> 14) & 0x3,
        "access_name": ACCESS_NAMES[(code >> 14) & 0x3],
    }


def encode_ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    """CTL_CODE(DeviceType, Function, Method, Access) as an integer."""
    return ((device_type & 0xFFFF) << 16) | ((access & 0x3) << 14) | (
        (function & 0xFFF) << 2
    ) | (method & 0x3)


def _int_value(value, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer, got a boolean")
    if isinstance(value, str):
        try:
            value = int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError(f"{label} is not an integer: {value!r}") from exc
    if not isinstance(value, int):
        raise ValueError(f"{label} must be an integer, got {type(value).__name__}")
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{label} must be in [{minimum}, {maximum}] (0x{minimum:X}..0x{maximum:X}), "
            f"got {value} (0x{value:X})"
        )
    return value


def _component(value, label: str, maximum: int) -> int:
    return _int_value(value, label, 0, maximum)


def _resolve_ioctl(ioctl, ioctl_code) -> tuple[int, dict, list[str]]:
    """Return ``(code, decoded, notes)`` from loose ioctl facts."""
    notes: list[str] = []
    data: dict = {}
    if ioctl is None:
        data = {}
    elif isinstance(ioctl, int) and not isinstance(ioctl, bool):
        data = {"code": ioctl}
    elif isinstance(ioctl, dict):
        data = ioctl
    else:
        raise TypeError(
            "ioctl must be an ioctl_extract result dict, an integer code, or None"
        )

    entries = data.get("ioctl_codes")
    if isinstance(entries, list):
        if len(entries) == 1 and isinstance(entries[0], dict):
            data = {**data, **entries[0]}
            notes.append(
                "the single entry in ioctl['ioctl_codes'] was selected; pass "
                "the specific entry to make the choice explicit"
            )
        elif len(entries) > 1:
            raise ValueError(
                f"ioctl facts contain {len(entries)} IOCTL codes; pass the "
                "specific entry, e.g. ioctl={'code': <value>, 'ctl_code': {...}}"
            )

    raw_code = None
    for key in ("code", "ioctl_code", "code_hex"):
        if data.get(key) is not None:
            raw_code = data[key]
            break
    if ioctl_code is not None:
        if raw_code is not None:
            supplied = _int_value(raw_code, "ioctl.code", 0, 0xFFFFFFFF)
            explicit = _int_value(ioctl_code, "ioctl_code", 0, 0xFFFFFFFF)
            if supplied != explicit:
                raise ValueError(
                    f"ioctl code conflict: ioctl facts say 0x{supplied:08X}, "
                    f"but ioctl_code=0x{explicit:08X}"
                )
        raw_code = ioctl_code

    components = data.get("ctl_code") if isinstance(data.get("ctl_code"), dict) else {}
    top_level = {
        key: data[key]
        for key in ("device_type", "function", "method", "access")
        if data.get(key) is not None
    }
    if top_level:
        if components and any(key in components for key in top_level):
            for key, value in top_level.items():
                if key in components and components[key] != value:
                    raise ValueError(
                        f"ioctl facts disagree about {key}: ctl_code={components[key]!r}, "
                        f"top-level={value!r}"
                    )
        components = {**top_level, **components}

    if raw_code is not None:
        code = _int_value(raw_code, "ioctl code", 0, 0xFFFFFFFF)
        decoded = decode_ctl_code(code)
        if components:
            for key in ("device_type", "function", "method", "access"):
                if key in components:
                    supplied = _component(
                        components[key],
                        f"ctl_code.{key}",
                        0xFFFF if key == "device_type" else (0xFFF if key == "function" else 0x3),
                    )
                    if supplied != decoded[key]:
                        raise ValueError(
                            f"ioctl code 0x{code:08X} decodes to {key}={decoded[key]} "
                            f"but the supplied ctl_code says {supplied}"
                        )
        return code, decoded, notes

    if not components:
        raise ValueError(
            "no IOCTL code: pass ioctl={'code': ...} or "
            "ioctl={'ctl_code': {'device_type','function','method','access'}}"
        )

    missing = [
        key
        for key in ("device_type", "function", "method", "access")
        if key not in components
    ]
    if missing:
        raise ValueError(
            "ctl_code is incomplete; missing " + ", ".join(missing)
        )
    device_type = _component(components["device_type"], "ctl_code.device_type", 0xFFFF)
    function = _component(components["function"], "ctl_code.function", 0xFFF)
    method = _component(components["method"], "ctl_code.method", 0x3)
    access = _component(components["access"], "ctl_code.access", 0x3)
    code = encode_ctl_code(device_type, function, method, access)
    notes.append(
        "IOCTL value was encoded from CTL_CODE fields; verify it against the "
        "driver's dispatch comparison before trusting it."
    )
    return code, decode_ctl_code(code), notes


# ---------------------------------------------------------------------------
# Device path handling
# ---------------------------------------------------------------------------

def _device_paths(device_name: str) -> tuple[str, list[str], str]:
    """Return ``(primary_win32_path, alternatives, source)``."""
    if not isinstance(device_name, str) or not device_name.strip():
        raise ValueError("device_name must be a non-empty string")
    name = device_name.strip()
    if "\r" in name or "\n" in name:
        raise ValueError("device_name must not contain newlines")
    lower = name.lower()

    if lower.startswith("\\\\.\\") or lower.startswith("\\\\?\\"):
        return name, [name], "as-given"
    if lower.startswith("\\device\\"):
        rest = name[len("\\Device\\"):]
        primary = "\\\\.\\" + rest
        return primary, [primary, "\\\\?\\GLOBALROOT" + name], "derived-from-nt-path"
    if lower.startswith("\\dosdevices\\"):
        rest = name[len("\\DosDevices\\"):]
        primary = "\\\\.\\" + rest
        return primary, [primary], "derived-from-nt-path"
    if lower.startswith("\\??\\"):
        rest = name[len("\\??\\"):]
        primary = "\\\\.\\" + rest
        return primary, [primary], "derived-from-nt-path"
    if name.startswith("\\"):
        base = name.rsplit("\\", 1)[-1]
        primary = "\\\\.\\" + base
        return primary, [primary, "\\\\?\\GLOBALROOT" + name], "derived-from-nt-path"
    return "\\\\.\\" + name, ["\\\\.\\" + name], "as-given"


def _c_wide(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'L"{escaped}"'


def _comment_safe(value: str) -> str:
    return value.replace("*/", "* /").replace("\r", " ").replace("\n", " ")


# ---------------------------------------------------------------------------
# Buffer code per METHOD
# ---------------------------------------------------------------------------

_METHOD_COMMENTS = {
    METHOD_BUFFERED: (
        " * METHOD_BUFFERED (0): the I/O manager allocates ONE system buffer of\n"
        " * max(InputBufferLength, OutputBufferLength), copies the input into\n"
        " * Irp->AssociatedIrp.SystemBuffer, and copies OutputBufferLength bytes\n"
        " * back to the user output buffer. The driver never sees the user\n"
        " * addresses below; both can be ordinary heap memory."
    ),
    METHOD_IN_DIRECT: (
        " * METHOD_IN_DIRECT (1): the INPUT buffer is copied into the system buffer\n"
        " * like METHOD_BUFFERED. The OUTPUT buffer is probed and locked as an MDL\n"
        " * (Irp->MdlAddress); the driver maps it with MmGetSystemAddressForMdlSafe.\n"
        " * The output buffer below is page-aligned and committed so the lock\n"
        " * always succeeds."
    ),
    METHOD_OUT_DIRECT: (
        " * METHOD_OUT_DIRECT (2): identical buffering to METHOD_IN_DIRECT --\n"
        " * input is a system-buffer copy, output is described by an MDL\n"
        " * (Irp->MdlAddress) -- but the contract is that the driver writes\n"
        " * results into the output buffer. The output buffer below is\n"
        " * page-aligned and committed."
    ),
    METHOD_NEITHER: (
        " * METHOD_NEITHER (3): NO I/O manager buffering. The driver receives\n"
        " * Parameters.DeviceIoControl.Type3InputBuffer and Irp->UserBuffer as raw\n"
        " * user-mode pointers; probing, alignment and access checks are entirely\n"
        " * the driver's responsibility. Both buffers are page-aligned VirtualAlloc\n"
        " * regions so deliberate misalignment/probe experiments can be built by\n"
        " * changing this block."
    ),
}

_BUFFER_SEMANTICS = {
    METHOD_BUFFERED: {
        "input": "copied by the I/O manager into Irp->AssociatedIrp.SystemBuffer",
        "output": "written by the driver into the same system buffer, then copied back to the user output buffer",
        "notes": ["input and output share one kernel allocation sized max(in, out)"],
    },
    METHOD_IN_DIRECT: {
        "input": "system-buffer copy (Irp->AssociatedIrp.SystemBuffer)",
        "output": "MDL-locked user buffer (Irp->MdlAddress); driver maps it with MmGetSystemAddressForMdlSafe",
        "notes": [
            "output allocation is page-aligned and committed so MmProbeAndLockPages succeeds",
            "input length is what the driver can read; output length is what it can write",
        ],
    },
    METHOD_OUT_DIRECT: {
        "input": "system-buffer copy (Irp->AssociatedIrp.SystemBuffer)",
        "output": "MDL-locked user buffer (Irp->MdlAddress); the driver writes results into it",
        "notes": [
            "output allocation is page-aligned and committed so MmProbeAndLockPages succeeds",
            "pass a meaningful OUTPUT_LENGTH: a zero-length output still gets an MDL",
        ],
    },
    METHOD_NEITHER: {
        "input": "raw user pointer in Parameters.DeviceIoControl.Type3InputBuffer (no I/O-manager probe)",
        "output": "raw user pointer in Irp->UserBuffer (no I/O-manager probe)",
        "notes": [
            "the driver must call ProbeForRead/ProbeForWrite itself; a buggy driver may fault directly",
            "both VirtualAlloc regions are page-aligned; vary alignment to test probe edge cases",
        ],
    },
}


def _alloc_blocks(method: int) -> tuple[str, str]:
    heap_input = (
        "    size_t alloc_input = input_length ? (size_t)input_length : 1u;\n"
        "    unsigned char *input = (unsigned char *)HeapAlloc(\n"
        "        GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_input);"
    )
    heap_output = (
        "    size_t alloc_output = output_length ? (size_t)output_length : 1u;\n"
        "    unsigned char *output = (unsigned char *)HeapAlloc(\n"
        "        GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_output);"
    )
    page_input = (
        "    SIZE_T alloc_input = ((SIZE_T)(input_length ? input_length : 1u)\n"
        "                          + 0x0FFFu) & ~(SIZE_T)0x0FFFu;\n"
        "    unsigned char *input = (unsigned char *)VirtualAlloc(\n"
        "        NULL, alloc_input, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);"
    )
    page_output = (
        "    SIZE_T alloc_output = ((SIZE_T)(output_length ? output_length : 1u)\n"
        "                           + 0x0FFFu) & ~(SIZE_T)0x0FFFu;\n"
        "    unsigned char *output = (unsigned char *)VirtualAlloc(\n"
        "        NULL, alloc_output, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);"
    )
    heap_free = (
        "    if (input != NULL) { HeapFree(GetProcessHeap(), 0, input); }\n"
        "    if (output != NULL) { HeapFree(GetProcessHeap(), 0, output); }"
    )
    mixed_free = (
        "    if (input != NULL) { HeapFree(GetProcessHeap(), 0, input); }\n"
        "    if (output != NULL) { VirtualFree(output, 0, MEM_RELEASE); }"
    )
    virtual_free = (
        "    if (input != NULL) { VirtualFree(input, 0, MEM_RELEASE); }\n"
        "    if (output != NULL) { VirtualFree(output, 0, MEM_RELEASE); }"
    )

    if method == METHOD_BUFFERED:
        alloc = heap_input + "\n" + heap_output
        free = heap_free
    elif method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
        alloc = heap_input + "\n" + page_output
        free = mixed_free
    else:
        alloc = page_input + "\n" + page_output
        free = virtual_free

    error_cleanup = "\n".join("    " + line for line in free.splitlines())
    alloc += (
        "\n\n    if (input == NULL || output == NULL) {\n"
        "        error = GetLastError();\n"
        '        fprintf(stderr, "buffer allocation failed: GetLastError()=%lu\\n",\n'
        "                (unsigned long)error);\n"
        f"{error_cleanup}\n"
        "        return 1;\n"
        "    }"
    )
    return alloc, free


# ---------------------------------------------------------------------------
# C source template
# ---------------------------------------------------------------------------

_SOURCE_TEMPLATE = Template(r"""/*
 * DRA PoC -- generated for authorized local driver research.
 * GENERATOR: dra.tools.tools.poc_generate (source only; not compiled or run).
 *
 * Target device : ${device_display}
 * Win32 path    : ${device_path}
 * IOCTL code    : ${ioctl_hex}
 * CTL_CODE      : ${ctl_macro}
 * Buffers       : input ${input_length} (0x${input_length_hex}) bytes,
 *                 output ${output_length} (0x${output_length_hex}) bytes,
 *                 fill byte 0x${fill_byte_hex}
 *
 * AUTHORIZATION / SAFETY
 *   ${authorization}
 *
${method_comment}
 *
 * Runtime length variation (minimal fuzz loop):
 *   poc.exe [input_length] [fill_byte] [output_length]
 * Defaults come from the #defines below.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#define IOCTL_CODE      ${ioctl_hex}u
#define DEVICE_PATH     ${device_c}
#define INPUT_LENGTH    ${input_length}u
#define OUTPUT_LENGTH   ${output_length}u
#define FILL_BYTE       ${fill_byte}

${template_decl}

static void fill_input(unsigned char *buffer, size_t length, unsigned int fill)
{
    size_t i;
    for (i = 0; i < kTemplateLength && i < length; ++i) {
        buffer[i] = kTemplate[i];
    }
    for (; i < length; ++i) {
        buffer[i] = (unsigned char)fill;
    }
}

static void hexdump(const char *label, const unsigned char *data, size_t length)
{
    size_t i;
    printf("%s (%zu bytes):", label, length);
    for (i = 0; i < length; ++i) {
        if (i % 16 == 0) {
            printf("\n  %04zx  ", i);
        }
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    DWORD input_length = INPUT_LENGTH;
    DWORD output_length = OUTPUT_LENGTH;
    unsigned int fill = FILL_BYTE;
    DWORD bytes_returned = 0;
    DWORD error = 0;
    BOOL ok = FALSE;
    HANDLE device = INVALID_HANDLE_VALUE;

    if (argc > 1) {
        input_length = (DWORD)strtoul(argv[1], NULL, 0);
    }
    if (argc > 2) {
        fill = (unsigned int)strtoul(argv[2], NULL, 0);
    }
    if (argc > 3) {
        output_length = (DWORD)strtoul(argv[3], NULL, 0);
    }

${alloc_block}

    fill_input(input, input_length, fill);

    device = CreateFileW(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (device == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        fprintf(stderr, "CreateFileW(%ls) failed: GetLastError()=%lu (0x%08lX)\n",
                DEVICE_PATH, (unsigned long)error, (unsigned long)error);
${free_block_error}
        return 1;
    }

    SetLastError(ERROR_SUCCESS);
    ok = DeviceIoControl(
        device,
        (DWORD)IOCTL_CODE,
        input,
        input_length,
        output,
        output_length,
        &bytes_returned,
        NULL);
    error = GetLastError();

    if (!ok) {
        fprintf(stderr,
                "DeviceIoControl(0x%08X) failed: GetLastError()=%lu (0x%08lX)\n",
                (unsigned int)IOCTL_CODE, (unsigned long)error,
                (unsigned long)error);
    } else {
        printf("DeviceIoControl(0x%08X) succeeded: %lu bytes returned, "
               "GetLastError()=%lu\n",
               (unsigned int)IOCTL_CODE, (unsigned long)bytes_returned,
               (unsigned long)error);
    }

    hexdump("input", input, input_length);
    /* Dump the whole output allocation: METHOD_NEITHER drivers write through
     * the raw pointer even when Information (bytes_returned) is not set. */
    hexdump("output", output, output_length);

${free_block}
    CloseHandle(device);
    return ok ? 0 : 2;
}
""")


def _template_decl(template_bytes: bytes) -> str:
    if not template_bytes:
        return (
            "static const unsigned char kTemplate[1] = { 0 };\n"
            "static const size_t kTemplateLength = 0;"
        )
    lines = []
    chunk: list[str] = []
    for index, byte in enumerate(template_bytes):
        chunk.append(f"0x{byte:02X}")
        if len(chunk) == 12:
            lines.append("    " + ", ".join(chunk) + ",")
            chunk = []
    if chunk:
        lines.append("    " + ", ".join(chunk) + ",")
    body = "\n".join(lines)
    return (
        "static const unsigned char kTemplate[] = {\n"
        f"{body}\n"
        "};\n"
        "static const size_t kTemplateLength = "
        "sizeof(kTemplate) / sizeof(kTemplate[0]);"
    )


def _parse_template(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        result = bytearray()
        for index, item in enumerate(value):
            result.append(_int_value(item, f"input_template[{index}]", 0, 0xFF))
        return bytes(result)
    if isinstance(value, str):
        cleaned = re.sub(r"[^0-9a-fA-F]", "", re.sub(r"0[xX]", "", value))
        if not cleaned:
            raise ValueError("input_template string contains no hex digits")
        if len(cleaned) % 2:
            raise ValueError(
                "input_template hex string must contain an even number of digits"
            )
        return bytes.fromhex(cleaned)
    raise TypeError("input_template must be a hex string, list[int], or bytes")


def _sanitize_filename(device_name: str, code: int) -> str:
    base = device_name.rstrip("\\").rsplit("\\", 1)[-1]
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_") or "device"
    return f"poc_{base.lower()}_0x{code:08X}.c"


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@tool(
    "poc_generate",
    description=(
        "Generate compilable C source for an IOCTL PoC from real ioctl facts "
        "(code + CTL_CODE fields), with per-METHOD buffer handling, compile "
        "commands and run prerequisites. Source only; nothing is executed."
    ),
    risk_level=RiskLevel.HIGH,
    parameters_schema={
        "device_name": "device path, e.g. \\Device\\Beep, \\DosDevices\\Beep or \\\\.\\Beep",
        "ioctl": "ioctl_extract result dict, or {'code': int}, or {'ctl_code': {...}}",
        "ioctl_code": "int IOCTL value (optional if ioctl supplies one)",
        "input_length": "int input buffer length in bytes (default 0x40)",
        "output_length": "int output buffer length in bytes (default 0x40)",
        "fill_byte": "int 0..255 used to fill the input buffer (default 0x41)",
        "input_template": "hex string or list[int] placed at the start of the input",
        "output_dir": "optional directory to write the .c file into",
    },
)
def poc_generate(
    device_name: str | None = None,
    ioctl: dict | int | None = None,
    ioctl_code: int | None = None,
    input_length: int = 0x40,
    output_length: int = 0x40,
    fill_byte: int = 0x41,
    input_template: list[int] | str | bytes | None = None,
    output_dir: str | None = None,
) -> dict:
    """Build the PoC source and metadata; never runs it."""
    notes: list[str] = []
    code, decoded, code_notes = _resolve_ioctl(ioctl, ioctl_code)
    notes.extend(code_notes)

    if device_name is None and isinstance(ioctl, dict):
        device_name = ioctl.get("device_name")
        if device_name is None:
            names = ioctl.get("device_names") or []
            if names:
                device_name = names[0]
                notes.append(
                    "device_name was taken from ioctl['device_names'][0]; "
                    "confirm it is the device this IOCTL is dispatched for."
                )
    if not device_name:
        raise ValueError(
            "device_name is required (e.g. '\\\\Device\\\\Beep' or '\\\\\\\\.\\\\Beep')"
        )

    primary_path, alternatives, path_source = _device_paths(device_name)
    if path_source == "derived-from-nt-path":
        notes.append(
            f"device_name is an NT path; {primary_path!r} assumes a DosDevices "
            "symbolic link with the same base name. Verify it in WinObj or "
            "pass the real symbolic link instead. A symlink-free alternative "
            f"is {alternatives[-1]!r}."
        )
    in_len = _int_value(input_length, "input_length", 0, 0xFFFFFFFF)
    out_len = _int_value(output_length, "output_length", 0, 0xFFFFFFFF)
    fill = _int_value(fill_byte, "fill_byte", 0, 0xFF)
    template_bytes = _parse_template(input_template)
    if len(template_bytes) > in_len:
        notes.append(
            f"input_template is {len(template_bytes)} bytes but input_length is "
            f"{in_len}; the generated code truncates the template to the buffer "
            "length (intended for length-mutation runs)."
        )

    method = decoded["method"]
    method_name = decoded["method_name"]
    alloc_block, free_block = _alloc_blocks(method)
    ctl_macro = "CTL_CODE(0x{device_type:04X}, 0x{function:03X}, {method}, {access})".format(
        device_type=decoded["device_type"],
        function=decoded["function"],
        method=method_name,
        access=decoded["access_name"],
    )

    source = _SOURCE_TEMPLATE.substitute(
        device_display=_comment_safe(str(device_name)),
        device_path=_comment_safe(primary_path),
        ioctl_hex=f"0x{code:08X}",
        ctl_macro=ctl_macro,
        input_length=in_len,
        input_length_hex=f"{in_len:08X}",
        output_length=out_len,
        output_length_hex=f"{out_len:08X}",
        fill_byte=fill,
        fill_byte_hex=f"{fill:02X}",
        authorization=AUTHORIZATION_NOTICE,
        method_comment=_METHOD_COMMENTS[method],
        template_decl=_template_decl(template_bytes),
        alloc_block=alloc_block,
        free_block=free_block,
        free_block_error="\n".join("    " + line for line in free_block.splitlines()),
        device_c=_c_wide(primary_path),
    )

    filename = _sanitize_filename(str(device_name), code)
    exe_name = filename[:-2] + ".exe"
    compile_commands = {
        "cl": f"cl /nologo /W4 /O2 /DUNICODE /D_UNICODE {filename} /Fe:{exe_name}",
        "clang_cl": (
            f"clang-cl /nologo /W4 /O2 /DUNICODE /D_UNICODE {filename} "
            f"/Fe:{exe_name}"
        ),
        "output": exe_name,
        "notes": [
            "Run from an x64 (or x86) Native Tools Command Prompt so the MSVC "
            "include/link environment is configured.",
            "clang-cl needs the MSVC build tools for headers/linker: "
            "https://learn.microsoft.com/cpp/build/clang-support-msbuild",
        ],
    }

    run_prerequisites = [
        "Authorized lab only: use a disposable VM or a snapshot you can "
        "discard. Never run this against a production machine.",
        "Verify the target driver is loaded and the device interface exists "
        "(WinObj: \\GLOBAL?? or \\Device). If only \\Device\\X exists with no "
        "symbolic link, try the GLOBALROOT path listed in the source comment.",
        "If the driver is not WHQL-signed, enable test signing on the test VM: "
        "`bcdedit /set testsigning on`, then reboot.",
        "Load the driver under test: `sc.exe create <svc> type= kernel "
        "binPath= C:\\path\\to\\driver.sys` then `sc.exe start <svc>`.",
        "Run as the privilege level in your hypothesis. Many device ACLs "
        "require Administrator; unprivileged reachability must be proven, "
        "not assumed.",
        "To capture a crash stack, wire COM1 to a host pipe "
        "(LabProvider.set_kernel_debug_serial) and attach kd.exe before "
        "running the PoC.",
        "Take a VM snapshot before execution and restore it afterwards; "
        "assume any buggy IOCTL can bugcheck the guest.",
    ]

    written = False
    source_path = None
    if output_dir:
        directory = Path(output_dir).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / filename
        target.write_text(source, encoding="utf-8", newline="\n")
        written = True
        source_path = str(target.resolve())

    return {
        "tool": "poc_generate",
        "ioctl_code": code,
        "ioctl_code_hex": f"0x{code:08X}",
        "ctl_code": {
            **decoded,
            "device_type_hex": f"0x{decoded['device_type']:04X}",
            "function_hex": f"0x{decoded['function']:03X}",
            "macro": ctl_macro,
        },
        "device": {
            "input": str(device_name),
            "win32_path": primary_path,
            "alternatives": alternatives,
            "path_source": path_source,
        },
        "buffers": {
            "input_length": in_len,
            "output_length": out_len,
            "fill_byte": fill,
            "template_length": len(template_bytes),
            "template_truncated": len(template_bytes) > in_len,
        },
        "method": method,
        "method_name": method_name,
        "buffer_semantics": {
            "method": method,
            "method_name": method_name,
            **_BUFFER_SEMANTICS[method],
        },
        "source_filename": filename,
        "source": source,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "compile": compile_commands,
        "run_prerequisites": run_prerequisites,
        "authorization_notice": AUTHORIZATION_NOTICE,
        "written": written,
        "source_path": source_path,
        "notes": notes,
    }
