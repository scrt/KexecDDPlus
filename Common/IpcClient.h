#pragma once

#include <Windows.h>

class IpcClient
{
public:
    IpcClient();
    ~IpcClient();

    BOOL Connect();
    BOOL Disconnect();
    BOOL IsConnected();
    BOOL SendPingRequest();
    BOOL SendStopServerRequest();
    BOOL SendQueryCiOptionsRequest(OUT PDWORD CiOptions);
    BOOL SendDisableCiRequest();
    BOOL SendSetCiOptionsRequest(IN DWORD CiOptions);

private:
    HANDLE m_hPipeHandle;
    LPBYTE m_pbIoBuffer;

    BOOL ConnectToNamedPipe(OUT PHANDLE PipeHandle);
    BOOL SendAndReceive(IN OUT LPBYTE IoBuffer, IN DWORD RequestSize, OUT PDWORD ResponseSize);
};