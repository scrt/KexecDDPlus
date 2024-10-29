#pragma once

#include "nt.h"
#include <Windows.h>
#include <vector>

#define PAGE_SIZE 0x1000
#define WIDEH(x) L##x
#define WIDE(x) WIDEH(x)
#define PRINT_VERBOSE_FORMAT_A(f) "[*][%s] " f
#define PRINT_VERBOSE_FORMAT_U(f) WIDE(PRINT_VERBOSE_FORMAT_A(f))
#define PRINT_VERBOSE_A(format, ...) if (g_bPrintVerbose) { printf( PRINT_VERBOSE_FORMAT_A(format), __FUNCTION__, __VA_ARGS__ ); }
#define PRINT_VERBOSE(format, ...) if (g_bPrintVerbose) { wprintf( PRINT_VERBOSE_FORMAT_U(format), WIDE(__FUNCTION__), __VA_ARGS__ ); }
#define PRINT_ERROR_FORMAT_A(f) "[-][%s] " f
#define PRINT_ERROR_FORMAT_U(f) WIDE(PRINT_ERROR_FORMAT_A(f))
#define PRINT_ERROR_A(format, ...) printf( PRINT_ERROR_FORMAT_A(format), __FUNCTION__, __VA_ARGS__ )
#define PRINT_ERROR(format, ...) wprintf( PRINT_ERROR_FORMAT_U(format), WIDE(__FUNCTION__), __VA_ARGS__ )
#define PRINT_ERROR_WIN32(func) { PRINT_ERROR( "%ws failed, err=%d - ", func, GetLastError()); Common::PrintSystemError(GetLastError()); }
#define PRINT_ERROR_NT(func, status) { PRINT_ERROR( "%ws failed, err=0x%08x (%d) - ", func, status, RtlNtStatusToDosError(status)); Common::PrintSystemError(RtlNtStatusToDosError(status)); }
#define PRINT_WARNING_FORMAT_A(f) "[!] " f
#define PRINT_WARNING_FORMAT_U(f) WIDE(PRINT_WARNING_FORMAT_A(f))
#define PRINT_WARNING_A(format, ...) printf( PRINT_WARNING_FORMAT_A(format), __VA_ARGS__ )
#define PRINT_WARNING(format, ...) wprintf( PRINT_WARNING_FORMAT_U(format), __VA_ARGS__ )
#define PRINT_SUCCESS_FORMAT_A(f) "[+] " f
#define PRINT_SUCCESS_FORMAT_U(f) WIDE(PRINT_SUCCESS_FORMAT_A(f))
#define PRINT_SUCCESS_A(format, ...) printf( PRINT_SUCCESS_FORMAT_A(format), __VA_ARGS__ )
#define PRINT_SUCCESS(format, ...) wprintf( PRINT_SUCCESS_FORMAT_U(format), __VA_ARGS__ )

extern BOOL g_bPrintVerbose;

namespace Common
{
    class ImageSectionHeaderInfo
    {
    public:
        CHAR Name[9];
        DWORD VirtualAddress;
        DWORD VirtualSize;
        DWORD Characteristics;
    };

    VOID PrintSystemError(_In_ DWORD ErrorCode);
    LPVOID Alloc(_In_ SIZE_T Size);
    BOOL Free(_In_ LPVOID Mem);

    BOOL FindKernelModuleBaseAddress(_In_ LPCSTR ModuleName, _Inout_ PULONG_PTR ModuleAddress);
    BOOL EnumModuleSections(_In_ HMODULE Module, _Inout_ std::vector<ImageSectionHeaderInfo>& SectionList);
    BOOL FindModuleSection(_In_ HMODULE Module, _In_ LPCSTR SectionName, _Inout_ ImageSectionHeaderInfo& Section);
    BOOL IsWritableAddress(_In_ HMODULE Module, _In_ ULONG_PTR Address);
    BOOL FindPatternOffset(_In_ LPVOID Buffer, _In_ DWORD BufferSize, _In_ PBYTE Pattern, _In_ DWORD PatternSize, _Out_ PDWORD PatternOffset);
    BOOL FindGadgetOffset(_In_ LPCWSTR Module, _In_ PBYTE Gadget, _In_ DWORD GadgetSize, _Out_ PDWORD GadgetOffset);
    BOOL FindCiOptionsOffset(_Out_ PDWORD Offset);

    BOOL EnablePrivilege(_In_opt_ HANDLE Token, _In_ LPCWSTR Privilege);
    BOOL QueryServiceProcessId(_In_ LPCWSTR Service, _Out_ PDWORD ProcessId);
    BOOL OpenServiceToken(_In_ LPCWSTR Service, _Out_ PHANDLE Token);
    BOOL ImpersonateToken(_In_ HANDLE Token);
    BOOL RevertImpersonation();

    BOOL ForkProcessIntoServerSilo(_In_ HANDLE ServerSilo, _Out_ LPPROCESS_INFORMATION ProcessInformation);
}