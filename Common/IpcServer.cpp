#include "IpcServer.h"
#include "ipc.h"
#include "common.h"
#include <sddl.h>

IpcServer::IpcServer()
{
    m_hPipeHandle = INVALID_HANDLE_VALUE;
    m_pbIoBuffer = NULL;
    m_bIsInitialized = FALSE;
    m_bStopServer = FALSE;
    m_ksecClient = nullptr;

    if (!this->CreateCustomNamedPipe(&m_hPipeHandle, FALSE)) goto exit;
    if (!(m_pbIoBuffer = (LPBYTE)Common::Alloc(PAGE_SIZE))) goto exit;

    m_bIsInitialized = TRUE;

exit:
    return;
}

IpcServer::~IpcServer()
{
    if (m_pbIoBuffer) Common::Free(m_pbIoBuffer);
    if (m_hPipeHandle && m_hPipeHandle != INVALID_HANDLE_VALUE) CloseHandle(m_hPipeHandle);
}

BOOL IpcServer::Listen()
{
    BOOL bResult = FALSE, bClientConnected = FALSE;
    DWORD dwBytesRead, dwBytesWritten, dwResponseSize = 0;

    bClientConnected = ConnectNamedPipe(this->m_hPipeHandle, NULL);
    if (!bClientConnected && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        PRINT_ERROR_WIN32(L"ConnectNamedPipe");
        goto exit;
    }

    while (!m_bStopServer)
    {
        ZeroMemory(this->m_pbIoBuffer, PAGE_SIZE);

        if (!ReadFile(this->m_hPipeHandle, this->m_pbIoBuffer, PAGE_SIZE, &dwBytesRead, NULL) || dwBytesRead == 0)
        {
            PRINT_ERROR_WIN32(L"ReadFile");
            break;
        }

        if (!this->ProcessRequest(m_pbIoBuffer, &dwResponseSize))
        {
            PRINT_ERROR(L"Fail to process request.\n");
            break;
        }

        if (!WriteFile(this->m_hPipeHandle, this->m_pbIoBuffer, dwResponseSize, &dwBytesWritten, NULL) || dwBytesWritten != dwResponseSize)
        {
            PRINT_ERROR_WIN32(L"WriteFile");
            break;
        }

        if (!FlushFileBuffers(this->m_hPipeHandle))
        {
            PRINT_ERROR_WIN32(L"FlushFileBuffers");
            break;
        }

        bResult = TRUE;
    }

exit:
    if (bClientConnected && this->m_hPipeHandle != INVALID_HANDLE_VALUE) DisconnectNamedPipe(this->m_hPipeHandle);

    return bResult;
}

BOOL IpcServer::ListenInThread(OUT PHANDLE ThreadHandle)
{
    BOOL bResult = FALSE;
    HANDLE hThread = NULL;

    if (!(hThread = CreateThread(NULL, 0, ListenThread, this, 0, NULL)))
    {
        PRINT_ERROR_WIN32(L"CreateThread");
        goto exit;
    }

    *ThreadHandle = hThread;
    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcServer::Stop()
{
    this->m_bStopServer = TRUE;

    return TRUE;
}

BOOL IpcServer::IsInitialized() const
{
    return m_bIsInitialized;
}

BOOL IpcServer::SetKsecClient(IN KsecDD* Ksec)
{
    if (this->m_ksecClient)
    {
        PRINT_ERROR(L"A KsecDD client is already set.\n");
        return FALSE;
    }
    else
    {
        this->m_ksecClient = Ksec;
        return TRUE;
    }
}

BOOL IpcServer::CreateCustomNamedPipe(OUT PHANDLE PipeHandle, IN BOOL Async)
{
    BOOL bResult = FALSE;
    LPWSTR pwszPipeName = NULL;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    DWORD dwOpenMode, dwPipeMode, dwMaxInstances;

    if (!(pwszPipeName = (LPWSTR)Common::Alloc(MAX_PATH * sizeof(WCHAR)))) goto exit;

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", IPC_NAMED_PIPE_NAME);

    dwOpenMode = PIPE_ACCESS_DUPLEX | (Async ? FILE_FLAG_OVERLAPPED : 0);
    dwPipeMode = PIPE_TYPE_BYTE | PIPE_WAIT;
    dwMaxInstances = PIPE_UNLIMITED_INSTANCES;

    hPipe = CreateNamedPipeW(pwszPipeName, dwOpenMode, dwPipeMode, dwMaxInstances, PAGE_SIZE, PAGE_SIZE, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        PRINT_ERROR_WIN32(L"CreateNamedPipeW");
        goto exit;
    }

    *PipeHandle = hPipe;
    bResult = TRUE;

exit:
    if (pwszPipeName) Common::Free(pwszPipeName);

    return bResult;
}

BOOL IpcServer::ProcessRequest(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    BOOL bResult = FALSE;
    DWORD dwType = 0;
    MessageType type;

    dwType = ((PIPC_REQUEST_HEADER)IoBuffer)->Type;
    if (dwType == 0 || dwType >= static_cast<DWORD>(MessageType::MaxValue))
    {
        PRINT_ERROR(L"Message type value out of range: %d\n", dwType);
        goto exit;
    }

    type = static_cast<MessageType>(dwType);
    switch (type)
    {
    case MessageType::Ping:
        bResult = this->DoPing(IoBuffer, ResponseSize);
        break;
    case MessageType::StopServer:
        bResult = this->DoStopServer(IoBuffer, ResponseSize);
        break;
    case MessageType::QueryCiOptions:
        bResult = this->DoQueryCiOptions(IoBuffer, ResponseSize);
        break;
    case MessageType::DisableCi:
        bResult = this->DoDisableCi(IoBuffer, ResponseSize);
        break;
    case MessageType::SetCiOptions:
        bResult = this->DoSetCiOptions(IoBuffer, ResponseSize);
        break;
    case MessageType::MaxValue:
        break;
    default:
        break;
    }

exit:
    return bResult;
}

BOOL IpcServer::DoPing(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    PIPC_REQUEST_PING req = (PIPC_REQUEST_PING)IoBuffer;
    PIPC_RESPONSE_PING resp = (PIPC_RESPONSE_PING)IoBuffer;

    if (_wcsicmp(req->Message, L"PING") == 0)
    {
        resp->Header.Type = static_cast<DWORD>(MessageType::Ping);
        resp->Header.Result = TRUE;
        resp->Header.Status = 0;

        swprintf_s(resp->Message, sizeof(resp->Message) / sizeof(*resp->Message), L"%ws", L"PONG");
    }
    else
    {
        resp->Header.Type = static_cast<DWORD>(MessageType::Ping);
        resp->Header.Result = FALSE;
        resp->Header.Status = 0;
    }

    *ResponseSize = sizeof(*resp);

    return TRUE;
}

BOOL IpcServer::DoStopServer(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    PIPC_REQUEST_STOP_SERVER req = (PIPC_REQUEST_STOP_SERVER)IoBuffer;
    PIPC_RESPONSE_STOP_SERVER resp = (PIPC_RESPONSE_STOP_SERVER)IoBuffer;

    resp->Header.Type = static_cast<DWORD>(MessageType::StopServer);
    resp->Header.Result = TRUE;
    resp->Header.Status = 0;

    *ResponseSize = sizeof(*resp);

    this->m_bStopServer = TRUE;

    return TRUE;
}

BOOL IpcServer::DoQueryCiOptions(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    PIPC_REQUEST_QUERY_CI_OPTIONS req = (PIPC_REQUEST_QUERY_CI_OPTIONS)IoBuffer;
    PIPC_RESPONSE_QUERY_CI_OPTIONS resp = (PIPC_RESPONSE_QUERY_CI_OPTIONS)IoBuffer;
    DWORD dwCiOptions;
    BOOL bSuccess;

    if (!this->m_ksecClient)
    {
        PRINT_ERROR(L"KsecDD not yet initialized.\n");
        return FALSE;
    }

    bSuccess = this->m_ksecClient->QueryCiOptionsValue(&dwCiOptions);

    resp->Header.Type = static_cast<DWORD>(MessageType::QueryCiOptions);
    resp->Header.Result = bSuccess;
    resp->Header.Status = 0;
    resp->CiOptions = dwCiOptions;

    *ResponseSize = sizeof(*resp);

    return TRUE;
}

BOOL IpcServer::DoDisableCi(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    PIPC_REQUEST_DISABLE_CI req = (PIPC_REQUEST_DISABLE_CI)IoBuffer;
    PIPC_RESPONSE_DISABLE_CI resp = (PIPC_RESPONSE_DISABLE_CI)IoBuffer;
    BOOL bSuccess;

    if (!this->m_ksecClient)
    {
        PRINT_ERROR(L"KsecDD not yet initialized.\n");
        return FALSE;
    }

    bSuccess = this->m_ksecClient->SetCiOptionsValue(0);

    resp->Header.Type = static_cast<DWORD>(MessageType::DisableCi);
    resp->Header.Result = bSuccess;
    resp->Header.Status = 0;

    *ResponseSize = sizeof(*resp);

    return TRUE;
}

BOOL IpcServer::DoSetCiOptions(IN OUT LPBYTE IoBuffer, OUT PDWORD ResponseSize)
{
    PIPC_REQUEST_SET_CI_OPTIONS req = (PIPC_REQUEST_SET_CI_OPTIONS)this->m_pbIoBuffer;
    PIPC_RESPONSE_SET_CI_OPTIONS resp = (PIPC_RESPONSE_SET_CI_OPTIONS)this->m_pbIoBuffer;
    BOOL bSuccess;

    if (!this->m_ksecClient)
    {
        PRINT_ERROR(L"KsecDD not yet initialized.\n");
        return FALSE;
    }

    bSuccess = this->m_ksecClient->SetCiOptionsValue(req->CiOptions);

    resp->Header.Type = static_cast<DWORD>(MessageType::SetCiOptions);
    resp->Header.Result = bSuccess;
    resp->Header.Status = 0;

    *ResponseSize = sizeof(*resp);

    return TRUE;
}

DWORD __stdcall IpcServer::ListenThread(IN LPVOID lpParameter)
{
    IpcServer* server = reinterpret_cast<IpcServer*>(lpParameter);
    
    server->Listen();

    return 0;
}