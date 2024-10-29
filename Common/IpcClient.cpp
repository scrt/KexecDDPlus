#include "IpcClient.h"
#include "common.h"
#include "ipc.h"

IpcClient::IpcClient()
{
    m_hPipeHandle = INVALID_HANDLE_VALUE;
    m_pbIoBuffer = NULL;

    if (!(m_pbIoBuffer = (LPBYTE)Common::Alloc(PAGE_SIZE))) goto exit;

exit:
    return;
}

IpcClient::~IpcClient()
{
    if (m_pbIoBuffer) Common::Free(m_pbIoBuffer);
    if (m_hPipeHandle && m_hPipeHandle != INVALID_HANDLE_VALUE) CloseHandle(m_hPipeHandle);
}

BOOL IpcClient::Connect()
{
    return this->ConnectToNamedPipe(&this->m_hPipeHandle);
}

BOOL IpcClient::Disconnect()
{
    if (!CloseHandle(this->m_hPipeHandle))
    {
        PRINT_ERROR_WIN32(L"CloseHandle");
        return FALSE;
    }

    this->m_hPipeHandle = INVALID_HANDLE_VALUE;

    return TRUE;
}

BOOL IpcClient::IsConnected()
{
    return this->m_hPipeHandle && this->m_hPipeHandle != INVALID_HANDLE_VALUE;
}

BOOL IpcClient::SendPingRequest()
{
    BOOL bResult = FALSE;
    PIPC_REQUEST_PING req = (PIPC_REQUEST_PING)this->m_pbIoBuffer;
    PIPC_RESPONSE_PING resp = (PIPC_RESPONSE_PING)this->m_pbIoBuffer;
    DWORD dwResponseSize;

    req->Header.Type = static_cast<DWORD>(MessageType::Ping);
    swprintf_s(req->Message, L"%s", L"PING");

    if (!this->SendAndReceive(this->m_pbIoBuffer, sizeof(*req), &dwResponseSize)) goto exit;

    if (!resp->Header.Result || _wcsicmp(resp->Message, L"PONG") != 0)
    {
        PRINT_ERROR(L"Ping request failed.\n");
        goto exit;
    }

    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcClient::SendStopServerRequest()
{
    BOOL bResult = FALSE;
    PIPC_REQUEST_STOP_SERVER req = (PIPC_REQUEST_STOP_SERVER)this->m_pbIoBuffer;
    PIPC_RESPONSE_STOP_SERVER resp = (PIPC_RESPONSE_STOP_SERVER)this->m_pbIoBuffer;
    DWORD dwResponseSize;

    req->Header.Type = static_cast<DWORD>(MessageType::StopServer);

    if (!this->SendAndReceive(this->m_pbIoBuffer, sizeof(*req), &dwResponseSize)) goto exit;

    if (dwResponseSize != sizeof(*resp))
    {
        PRINT_WARNING(L"Response message size mismatch (%d, should be %d).\n", dwResponseSize, (DWORD)sizeof(*resp));
    }

    if (!resp->Header.Result)
    {
        PRINT_ERROR(L"Stop Server request failed.\n");
        goto exit;
    }

    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcClient::SendQueryCiOptionsRequest(OUT PDWORD CiOptions)
{
    BOOL bResult = FALSE;
    PIPC_REQUEST_QUERY_CI_OPTIONS req = (PIPC_REQUEST_QUERY_CI_OPTIONS)this->m_pbIoBuffer;
    PIPC_RESPONSE_QUERY_CI_OPTIONS resp = (PIPC_RESPONSE_QUERY_CI_OPTIONS)this->m_pbIoBuffer;
    DWORD dwResponseSize;

    req->Header.Type = static_cast<DWORD>(MessageType::QueryCiOptions);

    if (!this->SendAndReceive(this->m_pbIoBuffer, sizeof(*req), &dwResponseSize)) goto exit;

    if (dwResponseSize != sizeof(*resp))
    {
        PRINT_WARNING(L"Response message size mismatch (%d, should be %d).\n", dwResponseSize, (DWORD)sizeof(*resp));
    }

    if (!resp->Header.Result)
    {
        PRINT_ERROR(L"Query Ci Options request failed.\n");
        goto exit;
    }

    *CiOptions = resp->CiOptions;
    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcClient::SendDisableCiRequest()
{
    BOOL bResult = FALSE;
    PIPC_REQUEST_DISABLE_CI req = (PIPC_REQUEST_DISABLE_CI)this->m_pbIoBuffer;
    PIPC_RESPONSE_DISABLE_CI resp = (PIPC_RESPONSE_DISABLE_CI)this->m_pbIoBuffer;
    DWORD dwResponseSize;

    req->Header.Type = static_cast<DWORD>(MessageType::DisableCi);

    if (!this->SendAndReceive(this->m_pbIoBuffer, sizeof(*req), &dwResponseSize)) goto exit;

    if (dwResponseSize != sizeof(*resp))
    {
        PRINT_WARNING(L"Response message size mismatch (%d, should be %d).\n", dwResponseSize, (DWORD)sizeof(*resp));
    }

    if (!resp->Header.Result)
    {
        PRINT_ERROR(L"Disable CI request failed.\n");
        goto exit;
    }

    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcClient::SendSetCiOptionsRequest(IN DWORD CiOptions)
{
    BOOL bResult = FALSE;
    PIPC_REQUEST_SET_CI_OPTIONS req = (PIPC_REQUEST_SET_CI_OPTIONS)this->m_pbIoBuffer;
    PIPC_RESPONSE_SET_CI_OPTIONS resp = (PIPC_RESPONSE_SET_CI_OPTIONS)this->m_pbIoBuffer;
    DWORD dwResponseSize;

    req->Header.Type = static_cast<DWORD>(MessageType::SetCiOptions);
    req->CiOptions = CiOptions;

    if (!this->SendAndReceive(m_pbIoBuffer, sizeof(*req), &dwResponseSize)) goto exit;

    if (dwResponseSize != sizeof(*resp))
    {
        PRINT_WARNING(L"Response message size mismatch (%d, should be %d).\n", dwResponseSize, (DWORD)sizeof(*resp));
    }

    if (!resp->Header.Result)
    {
        PRINT_ERROR(L"Set CI options request failed.\n");
        goto exit;
    }

    bResult = TRUE;

exit:
    return bResult;
}

BOOL IpcClient::ConnectToNamedPipe(OUT PHANDLE PipeHandle)
{
    BOOL bResult = FALSE;
    LPWSTR pwszPipeName = NULL;
    HANDLE hPipe = NULL;

    *PipeHandle = INVALID_HANDLE_VALUE;

    if (!(pwszPipeName = (LPWSTR)Common::Alloc(MAX_PATH * sizeof(WCHAR)))) goto exit;

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", IPC_NAMED_PIPE_NAME);

    hPipe = CreateFileW(pwszPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
    {
        PRINT_ERROR_WIN32(L"CreateFileW");
        goto exit;
    }

    *PipeHandle = hPipe;
    bResult = TRUE;

exit:
    if (pwszPipeName) Common::Free(pwszPipeName);

    return bResult;
}

BOOL IpcClient::SendAndReceive(IN OUT LPBYTE IoBuffer, IN DWORD RequestSize, OUT PDWORD ResponseSize)
{
    BOOL bResult = FALSE;
    DWORD dwBytesWritten, dwBytesRead;

    if (!WriteFile(this->m_hPipeHandle, IoBuffer, RequestSize, &dwBytesWritten, NULL))
    {
        PRINT_ERROR_WIN32(L"WriteFile");
        goto exit;
    }

    if (!ReadFile(this->m_hPipeHandle, IoBuffer, PAGE_SIZE, &dwBytesRead, NULL))
    {
        PRINT_ERROR_WIN32(L"ReadFile");
        goto exit;
    }

    *ResponseSize = dwBytesRead;
    bResult = TRUE;

exit:
    return bResult;
}