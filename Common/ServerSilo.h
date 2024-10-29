#pragma once

#include <Windows.h>

class ServerSilo
{
public:
    ServerSilo();
    ~ServerSilo();

    HANDLE GetHandle() const;
    LPWSTR GetRootDirectory() const;
    BOOL IsInitialized() const;

private:
    HANDLE m_hServerSilo;
    HANDLE m_hDeleteEvent;
    LPWSTR m_pwszRootDirectory;
    BOOL m_bIsInitialized;

    BOOL CreateJob(OUT PHANDLE Job, IN ACCESS_MASK Access);
    BOOL SetLimitFlags(IN HANDLE Job, IN DWORD Flags);
    BOOL ConvertJobToSilo(IN HANDLE Job);
    BOOL AssignProcess(IN HANDLE Job, IN HANDLE Process);
    BOOL SetRootDirectory(IN HANDLE Job, IN DWORD RootDirectoryFlags);
    BOOL CreateSilo(OUT PHANDLE Silo);
    BOOL SetSystemRoot(IN HANDLE Job, IN OPTIONAL LPCWSTR SystemRoot);
    BOOL QueryRootDirectory(IN HANDLE Job, OUT LPWSTR* RootDirectory);
    BOOL CreateDeviceDirectory(IN LPWSTR RootDirectory);
    BOOL Initialize(IN HANDLE Job, IN HANDLE DeleteEvent);
    BOOL Terminate(IN HANDLE Job, IN NTSTATUS ExitStatus);
    BOOL Close(IN HANDLE Job);
};