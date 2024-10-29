#pragma once

#include "KsecDD.h"
#include <Windows.h>

class IpcServer
{
public:
    IpcServer();
    ~IpcServer();

    BOOL Listen();
    BOOL ListenInThread(OUT PHANDLE ThreadHandle);
    BOOL Stop();
    BOOL IsInitialized() const;
    BOOL SetKsecClient(IN KsecDD* Ksec);

private:
    HANDLE m_hPipeHandle;
    LPBYTE m_pbIoBuffer;
    BOOL m_bIsInitialized;
    BOOL m_bStopServer;
    KsecDD* m_ksecClient;

    BOOL CreateCustomNamedPipe(OUT PHANDLE PipeHandle, IN BOOL Async);
    BOOL ProcessRequest(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);
    BOOL DoPing(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);
    BOOL DoStopServer(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);
    BOOL DoQueryCiOptions(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);
    BOOL DoDisableCi(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);
    BOOL DoSetCiOptions(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize);

    static DWORD WINAPI ListenThread(IN LPVOID lpParameter);
};