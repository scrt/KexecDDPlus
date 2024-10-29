#pragma once

#include "common.h"
#include <assert.h>

#define IPC_NAMED_PIPE_NAME L"KexecDDPlus"

enum class MessageType
{
    Ping = 1,
    StopServer,
    QueryCiOptions,
    DisableCi,
    SetCiOptions,
    MaxValue,
};

typedef struct _IPC_REQUEST_HEADER
{
    DWORD Type;
} IPC_REQUEST_HEADER, *PIPC_REQUEST_HEADER;
static_assert(sizeof(IPC_REQUEST_HEADER) < PAGE_SIZE, L"The size of IPC_REQUEST_HEADER is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_HEADER
{
    DWORD Type;
    BOOL Result;
    DWORD Status;
} IPC_RESPONSE_HEADER, *PIPC_RESPONSE_HEADER;
static_assert(sizeof(IPC_RESPONSE_HEADER) < PAGE_SIZE, L"The size of IPC_RESPONSE_HEADER is greater than PAGE_SIZE.");

typedef struct _IPC_REQUEST_PING
{
    IPC_REQUEST_HEADER Header;
    WCHAR Message[5];
} IPC_REQUEST_PING, *PIPC_REQUEST_PING;
static_assert(sizeof(IPC_REQUEST_PING) < PAGE_SIZE, L"The size of IPC_REQUEST_PING is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_PING
{
    IPC_RESPONSE_HEADER Header;
    WCHAR Message[5];
} IPC_RESPONSE_PING, *PIPC_RESPONSE_PING;
static_assert(sizeof(IPC_RESPONSE_PING) < PAGE_SIZE, L"The size of IPC_RESPONSE_PING is greater than PAGE_SIZE.");

typedef struct _IPC_REQUEST_STOP_SERVER
{
    IPC_REQUEST_HEADER Header;
} IPC_REQUEST_STOP_SERVER, *PIPC_REQUEST_STOP_SERVER;
static_assert(sizeof(IPC_REQUEST_STOP_SERVER) < PAGE_SIZE, L"The size of IPC_REQUEST_STOP_SERVER is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_STOP_SERVER
{
    IPC_RESPONSE_HEADER Header;
} IPC_RESPONSE_STOP_SERVER, *PIPC_RESPONSE_STOP_SERVER;
static_assert(sizeof(IPC_RESPONSE_STOP_SERVER) < PAGE_SIZE, L"The size of IPC_RESPONSE_STOP_SERVER is greater than PAGE_SIZE.");

typedef struct _IPC_REQUEST_QUERY_CI_OPTIONS
{
    IPC_REQUEST_HEADER Header;
} IPC_REQUEST_QUERY_CI_OPTIONS, *PIPC_REQUEST_QUERY_CI_OPTIONS;
static_assert(sizeof(IPC_REQUEST_QUERY_CI_OPTIONS) < PAGE_SIZE, L"The size of IPC_REQUEST_QUERY_CI_OPTIONS is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_QUERY_CI_OPTIONS
{
    IPC_RESPONSE_HEADER Header;
    DWORD CiOptions;
} IPC_RESPONSE_QUERY_CI_OPTIONS, *PIPC_RESPONSE_QUERY_CI_OPTIONS;
static_assert(sizeof(IPC_RESPONSE_QUERY_CI_OPTIONS) < PAGE_SIZE, L"The size of IPC_RESPONSE_QUERY_CI_OPTIONS is greater than PAGE_SIZE.");

typedef struct _IPC_REQUEST_DISABLE_CI
{
    IPC_REQUEST_HEADER Header;
} IPC_REQUEST_DISABLE_CI, *PIPC_REQUEST_DISABLE_CI;
static_assert(sizeof(IPC_REQUEST_DISABLE_CI) < PAGE_SIZE, L"The size of IPC_REQUEST_DISABLE_CI is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_DISABLE_CI
{
    IPC_RESPONSE_HEADER Header;
} IPC_RESPONSE_DISABLE_CI, *PIPC_RESPONSE_DISABLE_CI;
static_assert(sizeof(IPC_RESPONSE_DISABLE_CI) < PAGE_SIZE, L"The size of IPC_RESPONSE_DISABLE_CI is greater than PAGE_SIZE.");

typedef struct _IPC_REQUEST_SET_CI_OPTIONS
{
    IPC_REQUEST_HEADER Header;
    DWORD CiOptions;
} IPC_REQUEST_SET_CI_OPTIONS, *PIPC_REQUEST_SET_CI_OPTIONS;
static_assert(sizeof(IPC_REQUEST_SET_CI_OPTIONS) < PAGE_SIZE, L"The size of IPC_REQUEST_SET_CI_OPTIONS is greater than PAGE_SIZE.");

typedef struct _IPC_RESPONSE_SET_CI_OPTIONS
{
    IPC_RESPONSE_HEADER Header;
} IPC_RESPONSE_SET_CI_OPTIONS, *PIPC_RESPONSE_SET_CI_OPTIONS;
static_assert(sizeof(IPC_RESPONSE_SET_CI_OPTIONS) < PAGE_SIZE, L"The size of IPC_RESPONSE_SET_CI_OPTIONS is greater than PAGE_SIZE.");
