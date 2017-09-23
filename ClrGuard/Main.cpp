#include <windows.h>
#include <stdio.h>
#include <Sddl.h>
#include "ClrGuard.h"

#define PIPE_NAME "\\\\.\\pipe\\ClrGuard"

// Set this to 0 to block all but the whitelist
// set this to 1 to allow everything
DWORD g_DefaultAllowAction = 0;

typedef struct
{
    DWORD pid;
    DWORD msgSize;
} CMD_MSG;

const char * typeRefWhitelist[]
{
    "C877074345EA6EB82FCE5111CFF4AE6631CA0285AAD9018B7EACB86DADFB31EC", // PSDiagnostics v5.0
};

bool TypeRefWhitelist(char * typeRefHash)
{
    for (int i = 0; i < _countof(typeRefWhitelist); i++)
    {
        if (_stricmp(typeRefWhitelist[i], typeRefHash) == 0)
        {
            return true;
        }
    }

    return false;
}

void SaveModule(void * pMod, size_t modSize, char * fileName)
{
    HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("Error creating file\n");
    }

    DWORD dwWritten = 0;

    WriteFile(hFile, pMod, (DWORD)modSize, &dwWritten, 0);

    CloseHandle(hFile);

}

//
// Receives AssemblyLoad() events, logs the event, and will
// tell the target process to allow/block it based on content
//
DWORD WINAPI PipeRecvThread(LPVOID param)
{
    HANDLE hPipe = (HANDLE)param;
    HANDLE hProcess = 0;
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    DWORD cliPid = 0;
    CMD_MSG cmdMsg;
    BOOL bRet = FALSE;
    void * pBuf = 0;
    int allowAction = g_DefaultAllowAction;
    DWORD dwPathSz = 0;
    wchar_t processPath[MAX_PATH];
    char sha256[70];
    PEMeta peMeta;
    
    bRet = GetNamedPipeClientProcessId(hPipe, &cliPid);
    if (!bRet)
    {
        printf("Error getting client pid, last error %d\n", GetLastError());
        goto cleanup;
    }

    bRet = ReadFile(hPipe, &cmdMsg, sizeof(cmdMsg), &bytesRead, 0);

    if (!bRet || (bytesRead != sizeof(cmdMsg)))
    {
        printf("Error reading from pipe, last error %d\n", GetLastError());
        goto cleanup;
    }
    printf("Read command msg\n");

    if (cmdMsg.msgSize > 0x40000000)
    {
        printf("Invalid msgSize received %x\n", cmdMsg.msgSize);
        goto cleanup;
    }

    pBuf = malloc(cmdMsg.msgSize);

    if (pBuf == 0)
    {
        printf("Error allocating memory\n");
        goto cleanup;
    }

    bRet = ReadFile(hPipe, pBuf, cmdMsg.msgSize, &bytesRead, 0);

    if (!bRet || (bytesRead != cmdMsg.msgSize))
    {
        printf("Error reading from pipe, last error %d\n", GetLastError());
        goto cleanup;
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, cliPid);
    swprintf_s(processPath, _countof(processPath), L"unknown");
    if (0 == hProcess)
    {
        printf("Error opening process, last error %d\n", GetLastError());
    }
    else
    {
        dwPathSz = _countof(processPath);
        if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &dwPathSz))
        {
            printf("Error querying process path, last error %d\n", GetLastError());
        }
        CloseHandle(hProcess);
    }

    printf("+ Pid: %d, process: %ws, module size: %x\n", cliPid, processPath, cmdMsg.msgSize);

    if (GetSha256(pBuf, cmdMsg.msgSize, sha256, sizeof(sha256)))
    {
        printf("  Module hash: %s\n", sha256);
    }

    SaveModule(pBuf, cmdMsg.msgSize, sha256);

    if (!peMeta.ParseData(pBuf, cmdMsg.msgSize))
    {
        allowAction = 0;
        printf("Error parsing data\n");
    }
    else
    {
        printf("  TypeRef hash: %s\n", peMeta.typeRefHash);
        if (TypeRefWhitelist(peMeta.typeRefHash))
        {
            printf("whitelisted\n");
            allowAction = 1;
        }
    }

    LogEvent(cliPid, processPath, sha256, peMeta.typeRefHash, allowAction);

    bRet = WriteFile(hPipe, &allowAction, sizeof(allowAction), &bytesWritten, 0);


cleanup:
    if (pBuf != 0)
    {
        free(pBuf);
    }

    if (hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe);
    }

    return 0;
}

void ClrGuardServer()
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSd = 0;

    // Allow 'Everyone' RW access to the pipe
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"S:(ML;;NW;;;LW)D:(A;;GRGWRC;;;WD)", SDDL_REVISION_1, &pSd, 0))
    {
        printf("Error creating security descriptor, last error: %d\n", GetLastError());
        goto cleanup;
    }

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = false;
    sa.lpSecurityDescriptor = pSd;

    while (true)
    {
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        BOOL bConnected = FALSE;
        HANDLE hThread = 0;
        DWORD dwThreadId = 0;

        hPipe = CreateNamedPipeA(PIPE_NAME,
            PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |
            PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 0x50000, 0x50000, 0, &sa);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            printf("Error creating pipe, last error: %d\n", GetLastError());
            break;
        }

        bConnected = ConnectNamedPipe(hPipe, 0);

        if (!bConnected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            printf("Error connecting to pipe, last error %d\n", GetLastError());
            goto loop_cleanup;
        }

        printf("Client connected\n");

        hThread = CreateThread(0, 0, PipeRecvThread, hPipe, 0, &dwThreadId);

        if (hThread == 0)
        {
            printf("CreateThread failed, last error: %d\n", GetLastError());
            goto loop_cleanup;
        }

        // Don't close handle
        continue;

    loop_cleanup:
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPipe);
        }
        if (hThread != 0)
        {
            CloseHandle(hThread);
        }
    }

cleanup:
    if (pSd != 0)
    {
        LocalFree(pSd);
    }
}

int main(int argc, char ** argv)
{
    printf("-- CLRGuard --\n");

    const char * filePath = 0;

    for (int i = 1; i < argc; ++i)
    {
        const char *pArg = argv[i];

        if (0 == _stricmp(pArg, "-f"))
        {
            if (i + 1 < argc)
            {
                filePath = argv[i + 1];
                ++i;
            }
            else
            {
                printf("Missing param value\n");
                return 1;
            }
        }
        else if (0 == _stricmp(pArg, "-i"))
        {
            printf("Installing service..\n");
            ServiceInstall();
            return 0;
        }
        else if (0 == _stricmp(pArg, "-s"))
        {
            printf("Running as service..\n");
            ServiceEntry();
            return 0;
        }
        else if (0 == _stricmp(pArg, "-h"))
        {
            printf("ClrGuard options\n");
            printf("-i\t\t\tInstall as a service (named %ws)\n", SVCNAME);
            printf("-f <file>\t\tDump .NET PE info for target file\n");
            return 1;
        }
        else
        {
            printf("Unknown argument\n");
            return 1;
        }
    }

    if (filePath)
    {
        PEMeta peMeta;
        peMeta.DumpFileInfo(filePath);
        return 0;
    }

    ClrGuardServer();

    return 0;
}