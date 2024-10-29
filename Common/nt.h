#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_PROCESS_CLONED ((NTSTATUS)0x00000129L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h
// SYSTEM_INFORMATION_CLASS
#define SystemModuleInformation 11

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntioapi.h
// FILE_INFORMATION_CLASS (undocumented)
#define FileIoCompletionNotificationInformation 41

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
// PS_ATTRIBUTE_NUM (undocumented)
#define PsAttributeStdHandleInfo 10
#define PsAttributeJobList 19

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
// JOBOBJECTINFOCLASS (undocumented)
#define JobObjectSiloRootDirectory 37 // 0x25 - SILOOBJECT_ROOT_DIRECTORY
#define JobObjectServerSiloInitialize 40 // 0x28 - SERVERSILO_INIT_INFORMATION
#define JobObjectContainerTelemetryId 44 // 0x2c
#define JobObjectSiloSystemRoot 45 // 0x2d

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
// Job extended limits (undocumented)
#define JOB_OBJECT_LIMIT_SILO_READY 0x00400000

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
#define SILO_OBJECT_ROOT_DIRECTORY_SHADOW_ROOT 0x00000001
#define SILO_OBJECT_ROOT_DIRECTORY_INITIALIZE 0x00000002
#define SILO_OBJECT_ROOT_DIRECTORY_SHADOW_DOS_DEVICES 0x00000004
#define SILO_OBJECT_ROOT_DIRECTORY_ALL SILO_OBJECT_ROOT_DIRECTORY_SHADOW_ROOT | SILO_OBJECT_ROOT_DIRECTORY_INITIALIZE | SILO_OBJECT_ROOT_DIRECTORY_SHADOW_DOS_DEVICES

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)

#ifdef __cplusplus
extern "C" {
#endif

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntldr.h
    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntldr.h
    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _PS_ATTRIBUTE
    {
        ULONG_PTR Attribute;
        SIZE_T Size;
        union
        {
            ULONG_PTR Value;
            PVOID ValuePtr;
        };
        PSIZE_T ReturnLength;
    } PS_ATTRIBUTE, * PPS_ATTRIBUTE;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _PS_ATTRIBUTE_LIST
    {
        SIZE_T TotalLength;
        PS_ATTRIBUTE Attributes[1];
    } PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _PS_STD_HANDLE_INFO
    {
        union
        {
            ULONG Flags;
            struct
            {
                ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
                ULONG PseudoHandleMask : 3; // PS_STD_*
            };
        };
        ULONG StdHandleSubsystemType;
    } PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef enum _PS_STD_HANDLE_STATE
    {
        PsNeverDuplicate,
        PsRequestDuplicate, // duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
        PsAlwaysDuplicate, // always duplicate standard handles
        PsMaxStdHandleStates
    } PS_STD_HANDLE_STATE;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef enum _PS_CREATE_STATE
    {
        PsCreateInitialState,
        PsCreateFailOnFileOpen,
        PsCreateFailOnSectionCreate,
        PsCreateFailExeFormat,
        PsCreateFailMachineMismatch,
        PsCreateFailExeName, // Debugger specified
        PsCreateSuccess,
        PsCreateMaximumStates
    } PS_CREATE_STATE;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _PS_CREATE_INFO
    {
        SIZE_T Size;
        PS_CREATE_STATE State;
        union
        {
            // PsCreateInitialState
            struct
            {
                union
                {
                    ULONG InitFlags;
                    struct
                    {
                        UCHAR WriteOutputOnExit : 1;
                        UCHAR DetectManifest : 1;
                        UCHAR IFEOSkipDebugger : 1;
                        UCHAR IFEODoNotPropagateKeyState : 1;
                        UCHAR SpareBits1 : 4;
                        UCHAR SpareBits2 : 8;
                        USHORT ProhibitedImageCharacteristics : 16;
                    };
                };
                ACCESS_MASK AdditionalFileAccess;
            } InitState;

            // PsCreateFailOnSectionCreate
            struct
            {
                HANDLE FileHandle;
            } FailSection;

            // PsCreateFailExeFormat
            struct
            {
                USHORT DllCharacteristics;
            } ExeFormat;

            // PsCreateFailExeName
            struct
            {
                HANDLE IFEOKey;
            } ExeName;

            // PsCreateSuccess
            struct
            {
                union
                {
                    ULONG OutputFlags;
                    struct
                    {
                        UCHAR ProtectedProcess : 1;
                        UCHAR AddressSpaceOverride : 1;
                        UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                        UCHAR ManifestDetected : 1;
                        UCHAR ProtectedProcessLight : 1;
                        UCHAR SpareBits1 : 3;
                        UCHAR SpareBits2 : 8;
                        USHORT SpareBits3 : 16;
                    };
                };
                HANDLE FileHandle;
                HANDLE SectionHandle;
                ULONGLONG UserProcessParametersNative;
                ULONG UserProcessParametersWow64;
                ULONG CurrentParameterFlags;
                ULONGLONG PebAddressNative;
                ULONG PebAddressWow64;
                ULONGLONG ManifestAddress;
                ULONG ManifestSize;
            } SuccessState;
        };
    } PS_CREATE_INFO, * PPS_CREATE_INFO;

#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#define FILE_SKIP_SET_USER_EVENT_ON_FAST_IO 0x4

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntioapi.h
    typedef struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION
    {
        ULONG Flags;
    } FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, * PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _SILOOBJECT_ROOT_DIRECTORY
    {
        union
        {
            ULONG ControlFlags; // SILO_OBJECT_ROOT_DIRECTORY_*
            UNICODE_STRING Path;
        };
    } SILOOBJECT_ROOT_DIRECTORY, * PSILOOBJECT_ROOT_DIRECTORY;

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    typedef struct _SERVERSILO_INIT_INFORMATION
    {
        HANDLE DeleteEvent;
        BOOLEAN IsDownlevelContainer;
    } SERVERSILO_INIT_INFORMATION, * PSERVERSILO_INIT_INFORMATION;

    // https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
    typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2
    {
        JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        IO_COUNTERS IoInfo;
        SIZE_T ProcessMemoryLimit;
        SIZE_T JobMemoryLimit;
        SIZE_T PeakProcessMemoryUsed;
        SIZE_T PeakJobMemoryUsed;
        SIZE_T JobTotalMemoryLimit;
    } JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2, * PJOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2;

    _Success_(return != 0)
        _Must_inspect_result_
        NTSYSAPI
        BOOLEAN
        NTAPI
        RtlCreateUnicodeString(
            _Out_ PUNICODE_STRING DestinationString,
            _In_z_ PCWSTR SourceString
        );

    NTSYSAPI
        PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(
            IN      PVOID               ModuleAddress
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateUserProcess(
            _Out_ PHANDLE ProcessHandle,
            _Out_ PHANDLE ThreadHandle,
            _In_ ACCESS_MASK ProcessDesiredAccess,
            _In_ ACCESS_MASK ThreadDesiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
            _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
            _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
            _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
            _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
            _Inout_ PPS_CREATE_INFO CreateInfo,
            _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
        );

    // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtTerminateProcess(
            _In_opt_ HANDLE ProcessHandle,
            _In_ NTSTATUS ExitStatus
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtImpersonateThread(
            _In_ HANDLE ServerThreadHandle,
            _In_ HANDLE ClientThreadHandle,
            _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenEvent(
            _Out_ PHANDLE EventHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_ POBJECT_ATTRIBUTES ObjectAttributes
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtSetEvent(
            _In_ HANDLE EventHandle,
            _Out_opt_ PLONG PreviousState
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenDirectoryObject(
            _Out_ PHANDLE DirectoryHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_ POBJECT_ATTRIBUTES ObjectAttributes
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateDirectoryObjectEx(
            _Out_ PHANDLE DirectoryHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_ POBJECT_ATTRIBUTES ObjectAttributes,
            _In_ HANDLE ShadowDirectoryHandle,
            _In_ ULONG Flags
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtSetInformationFile(
            _In_ HANDLE FileHandle,
            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
            _In_reads_bytes_(Length) PVOID FileInformation,
            _In_ ULONG Length,
            _In_ FILE_INFORMATION_CLASS FileInformationClass
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateJobObject(
            _Out_ PHANDLE JobHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtSetInformationJobObject(
            _In_ HANDLE JobHandle,
            _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
            _In_reads_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
            _In_ ULONG JobObjectInformationLength
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtQueryInformationJobObject(
            _In_opt_ HANDLE JobHandle,
            _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
            _Out_writes_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
            _In_ ULONG JobObjectInformationLength,
            _Out_opt_ PULONG ReturnLength
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtTerminateJobObject(
            _In_ HANDLE JobHandle,
            _In_ NTSTATUS ExitStatus
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAssignProcessToJobObject(
            _In_ HANDLE JobHandle,
            _In_ HANDLE ProcessHandle
        );

#ifdef __cplusplus
}
#endif