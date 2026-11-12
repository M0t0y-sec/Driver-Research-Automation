/*
 * DraTestDriver -- deliberately vulnerable WDM driver used to validate the
 * DRA research pipeline end to end.
 *
 * PURPOSE
 *   This driver exists so the platform can be tested against a target whose
 *   bugs are known in advance. Every crash it produces is attributable by
 *   construction, which is what makes it usable as a pipeline fixture.
 *
 *   Do not install it on any machine you care about. It is not a sample for
 *   vulnerability reports.
 *
 * SURFACE
 *   \Device\DraTest  <->  \DosDevices\DraTest   (user path: \\.\DraTest)
 *
 *   IOCTL_DRA_STACK_OVERFLOW    0x222000  METHOD_BUFFERED
 *     Copies InputBufferLength bytes into a 64-byte stack buffer with no
 *     length check. Send more than 64 bytes to corrupt the kernel stack.
 *     Expected: 0x7F / 0x1A / 0x50 depending on where the overflow lands.
 *
 *   IOCTL_DRA_UNTRUSTED_POINTER 0x222007  METHOD_NEITHER
 *     Treats Type3InputBuffer as a UNICODE_STRING and reads Buffer[0]
 *     without ProbeForRead. Send a UNICODE_STRING whose Buffer is unmapped
 *     (for example 0x1) to fault inside the driver.
 *     Expected: 0xA or 0x50 with the driver's module in the stack.
 *
 *   IOCTL_DRA_SAFE_PING         0x222008  METHOD_BUFFERED
 *     Does nothing and returns STATUS_SUCCESS. Negative control: the
 *     pipeline must not report a finding for this path.
 *
 * BUILD
 *   See README.md. Requires Visual Studio 2022 plus the Windows 11 WDK.
 */

#include <ntddk.h>

#define DRA_DEVICE_NAME  L"\\Device\\DraTest"
#define DRA_SYMLINK_NAME L"\\DosDevices\\DraTest"

#define IOCTL_DRA_STACK_OVERFLOW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DRA_UNTRUSTED_POINTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRA_SAFE_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

static VOID DraUnload(PDRIVER_OBJECT DriverObject);
static NTSTATUS DraCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS DraDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, DRA_DEVICE_NAME);

    /*
     * Characteristics 0 leaves FILE_DEVICE_SECURE_OPEN off, so the default
     * device ACL applies and an unprivileged process can open \\.\DraTest.
     * That is the reachability the test needs.
     */
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symlinkName, DRA_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DraCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DraCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DraDeviceControl;
    DriverObject->DriverUnload = DraUnload;

    return STATUS_SUCCESS;
}

static VOID DraUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    RtlInitUnicodeString(&symlinkName, DRA_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

static NTSTATUS DraCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DraDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG controlCode;
    ULONG inputLength;
    PVOID systemBuffer;
    PVOID userInput;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    userInput = stack->Parameters.DeviceIoControl.Type3InputBuffer;
    status = STATUS_INVALID_DEVICE_REQUEST;

    switch (controlCode) {

    case IOCTL_DRA_STACK_OVERFLOW: {
        UCHAR stackBuffer[64];
        volatile UCHAR observed;

        RtlZeroMemory(stackBuffer, sizeof(stackBuffer));

        /* VULNERABLE: no comparison of inputLength against sizeof(stackBuffer). */
        if (inputLength > 0 && systemBuffer != NULL) {
            RtlCopyMemory(stackBuffer, systemBuffer, inputLength);
        }

        /* Keeps the copy observable so the compiler cannot drop it. */
        observed = stackBuffer[0];
        UNREFERENCED_PARAMETER(observed);

        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_DRA_UNTRUSTED_POINTER: {
        PUNICODE_STRING userString;
        volatile WCHAR firstChar;

        /* VULNERABLE: the user pointer is trusted without ProbeForRead. */
        if (inputLength >= sizeof(UNICODE_STRING) && userInput != NULL) {
            userString = (PUNICODE_STRING)userInput;
            firstChar = userString->Buffer[0];
            UNREFERENCED_PARAMETER(firstChar);
        }

        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_DRA_SAFE_PING:
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
