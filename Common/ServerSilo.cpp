#include "ServerSilo.h"
#include "common.h"
#include "nt.h"
#include <strsafe.h>

ServerSilo::ServerSilo()
{
    m_hServerSilo = NULL;
    m_hDeleteEvent = NULL;
    m_pwszRootDirectory = NULL;
    m_bIsInitialized = FALSE;

    if (!(m_hDeleteEvent = ::CreateEventW(NULL, TRUE, FALSE, NULL))) goto exit;

    if (!this->CreateSilo(&m_hServerSilo)) goto exit;
    if (!this->SetSystemRoot(m_hServerSilo, NULL)) goto exit;
    if (!this->QueryRootDirectory(m_hServerSilo, &m_pwszRootDirectory)) goto exit;
    if (!this->CreateDeviceDirectory(m_pwszRootDirectory)) goto exit;
    if (!this->Initialize(m_hServerSilo, m_hDeleteEvent)) goto exit;

    m_bIsInitialized = TRUE;

exit:
    return;
}

ServerSilo::~ServerSilo()
{
    if (m_hServerSilo)
    {
        this->Terminate(m_hServerSilo, STATUS_SUCCESS);
        this->Close(m_hServerSilo);
    }

    if (m_hDeleteEvent) CloseHandle(m_hDeleteEvent);
    if (m_pwszRootDirectory) Common::Free(m_pwszRootDirectory);
}

HANDLE ServerSilo::GetHandle() const
{
    return m_hServerSilo;
}

LPWSTR ServerSilo::GetRootDirectory() const
{
    return m_pwszRootDirectory;
}

BOOL ServerSilo::IsInitialized() const
{
    return m_bIsInitialized;
}

BOOL ServerSilo::CreateJob(OUT PHANDLE Job, IN ACCESS_MASK Access)
{
    NTSTATUS status;
    HANDLE hJob = NULL;

    *Job = NULL;

    status = NtCreateJobObject(&hJob, Access, NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtCreateJobObject", status);
        return FALSE;
    }

    *Job = hJob;

    return TRUE;
}

BOOL ServerSilo::SetLimitFlags(IN HANDLE Job, IN DWORD Flags)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2 info = { 0 };

    info.BasicLimitInformation.LimitFlags = Flags;

    status = NtSetInformationJobObject(Job, JobObjectExtendedLimitInformation, &info, sizeof(info));
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::ConvertJobToSilo(IN HANDLE Job)
{
    NTSTATUS status;

    status = NtSetInformationJobObject(Job, JobObjectCreateSilo, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::AssignProcess(IN HANDLE Job, IN HANDLE Process)
{
    NTSTATUS status;

    status = NtAssignProcessToJobObject(Job, Process);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtAssignProcessToJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::SetRootDirectory(IN HANDLE Job, IN DWORD RootDirectoryFlags)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    SILOOBJECT_ROOT_DIRECTORY sro = { 0 };

    sro.ControlFlags = RootDirectoryFlags;

    status = NtSetInformationJobObject(Job, (JOBOBJECTINFOCLASS)JobObjectSiloRootDirectory, &sro, sizeof(sro));
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::CreateSilo(OUT PHANDLE Silo)
{
    BOOL bResult = FALSE;
    HANDLE hJob = NULL;

    *Silo = NULL;

    if (!this->CreateJob(&hJob, JOB_OBJECT_ALL_ACCESS)) goto exit;
    if (!this->SetLimitFlags(hJob, JOB_OBJECT_LIMIT_SILO_READY)) goto exit;
    if (!this->ConvertJobToSilo(hJob)) goto exit;
    if (!this->AssignProcess(hJob, (HANDLE)-7)) goto exit;
    if (!this->SetRootDirectory(hJob, SILO_OBJECT_ROOT_DIRECTORY_ALL)) goto exit;

    *Silo = hJob;
    bResult = TRUE;

exit:
    return bResult;
}

BOOL ServerSilo::SetSystemRoot(IN HANDLE Job, IN OPTIONAL LPCWSTR SystemRoot)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    WCHAR wszWindowsDirectory[MAX_PATH];
    DWORD dwWindowsDirectoryLength;
    LPWSTR pwszSystemRoot = NULL;
    PUNICODE_STRING pusSystemRoot = NULL;

    if (!SystemRoot)
    {
        if (!GetWindowsDirectoryW(wszWindowsDirectory, MAX_PATH))
        {
            PRINT_ERROR_WIN32(L"GetSystemDirectoryW");
            goto exit;
        }

        // Remove trailing slash in system directory path
        dwWindowsDirectoryLength = (DWORD)wcslen(wszWindowsDirectory);
        if (dwWindowsDirectoryLength && wszWindowsDirectory[dwWindowsDirectoryLength - 1] == '\\')
            wszWindowsDirectory[dwWindowsDirectoryLength - 1] = '\0';
    }

    if (!(pusSystemRoot = (PUNICODE_STRING)Common::Alloc(sizeof(*pusSystemRoot)))) goto exit;

    if (!RtlCreateUnicodeString(pusSystemRoot, SystemRoot ? SystemRoot : wszWindowsDirectory))
    {
        PRINT_ERROR(L"RtlCreateUnicodeString failed.\n");
        goto exit;
    }

    status = NtSetInformationJobObject(Job, (JOBOBJECTINFOCLASS)JobObjectSiloSystemRoot, pusSystemRoot, sizeof(*pusSystemRoot));
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationJobObject", status);
        goto exit;
    }

    bResult = TRUE;

exit:
    if (pusSystemRoot)
    {
        if (pusSystemRoot->Buffer)
            RtlFreeUnicodeString(pusSystemRoot);
        Common::Free(pusSystemRoot);
    }

    return bResult;
}

BOOL ServerSilo::QueryRootDirectory(IN HANDLE Job, OUT LPWSTR* RootDirectory)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    ULONG len = 0;
    PSILOOBJECT_ROOT_DIRECTORY psrd = NULL;
    const DWORD dwBufferSize = 0x1000;
    LPWSTR pwszRootDirectory = NULL;
    DWORD dwRootDirectoryLength;

    *RootDirectory = NULL;

    if (!(psrd = (PSILOOBJECT_ROOT_DIRECTORY)Common::Alloc(dwBufferSize))) goto exit;

    status = NtQueryInformationJobObject(Job, (JOBOBJECTINFOCLASS)JobObjectSiloRootDirectory, psrd, dwBufferSize, &len);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtQueryInformationJobObject", status);
        goto exit;
    }

    dwRootDirectoryLength = (DWORD)wcslen(psrd->Path.Buffer);

    if (!(pwszRootDirectory = (LPWSTR)Common::Alloc((dwRootDirectoryLength + 1) * sizeof(*pwszRootDirectory)))) goto exit;
    StringCchPrintfW(pwszRootDirectory, dwRootDirectoryLength + 1, L"%ws", psrd->Path.Buffer);
    *RootDirectory = pwszRootDirectory;
    bResult = TRUE;

exit:
    if (!bResult && pwszRootDirectory) Common::Free(pwszRootDirectory);
    if (psrd) Common::Free(psrd);

    return bResult;
}

BOOL ServerSilo::CreateDeviceDirectory(IN LPWSTR RootDirectory)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    UNICODE_STRING usDevicePath = { 0 }, usSiloDevicePath = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    HANDLE hDeviceDirectory = NULL, hSiloDeviceDirectory = NULL;
    WCHAR wszSiloDevicePath[MAX_PATH] = { 0 };

    RtlInitUnicodeString(&usDevicePath, L"\\Device");
    InitializeObjectAttributes(&oa, &usDevicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenDirectoryObject(&hDeviceDirectory, MAXIMUM_ALLOWED, &oa);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtOpenDirectoryObject", status);
        goto exit;
    }

    StringCchPrintfW(wszSiloDevicePath, MAX_PATH, L"%ws\\Device", RootDirectory);

    RtlInitUnicodeString(&usSiloDevicePath, wszSiloDevicePath);
    InitializeObjectAttributes(&oa, &usSiloDevicePath, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_OPENIF, NULL, NULL);

    status = NtCreateDirectoryObjectEx(&hSiloDeviceDirectory, MAXIMUM_ALLOWED, &oa, hDeviceDirectory, 0);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtCreateDirectoryObjectEx", status);
        goto exit;
    }

    bResult = TRUE;

exit:
    if (hSiloDeviceDirectory) NtClose(hSiloDeviceDirectory);
    if (hDeviceDirectory) NtClose(hDeviceDirectory);

    return bResult;
}

BOOL ServerSilo::Initialize(IN HANDLE Job, IN HANDLE DeleteEvent)
{
    NTSTATUS status;
    SERVERSILO_INIT_INFORMATION init = { 0 };
    
    init.DeleteEvent = DeleteEvent;
    init.IsDownlevelContainer = FALSE;

    status = NtSetInformationJobObject(Job, (JOBOBJECTINFOCLASS)JobObjectServerSiloInitialize, &init, sizeof(init));
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        status = NtSetInformationJobObject(Job, (JOBOBJECTINFOCLASS)JobObjectServerSiloInitialize, &DeleteEvent, sizeof(DeleteEvent));
    }

    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtSetInformationJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::Terminate(IN HANDLE Job, IN NTSTATUS ExitStatus)
{
    NTSTATUS status;

    status = NtTerminateJobObject(Job, ExitStatus);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtTerminateJobObject", status);
        return FALSE;
    }

    return TRUE;
}

BOOL ServerSilo::Close(IN HANDLE Job)
{
    NTSTATUS status;

    status = NtClose(Job);

    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtClose", status);
        return FALSE;
    }

    return TRUE;
}