#include "pipe.h"
#include "ClrHook.h"

HANDLE ConnectPipe()
{
    WORD retVal = 0;
    DWORD pipeMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    hPipe = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE,
        0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, 0);

    if (INVALID_HANDLE_VALUE == hPipe)
    {
        debug_print("Error connecting to pipe, last error: %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    if (!SetNamedPipeHandleState(hPipe, &pipeMode, 0, 0))
    {
        debug_print("Error setting pipe state, last error: %d\n", GetLastError());
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    return hPipe;
}

//
// Notifies ClrGuard.exe that an ImageLoad event has happend. Receives
// a response with the allow/block decision.
//
bool ReportLoadImage(void * pBuffer, DWORD imageSize)
{
    BOOL bRet = FALSE;
    bool allowLoad = true;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    DWORD dwBytesWritten = 0;
    DWORD dwBytesRead = 0;
    CMD_MSG cmdMsg;
    cmdMsg.msgSize = imageSize;
    cmdMsg.pid = GetCurrentProcessId();
    int iBuf = 0;

    hPipe = ConnectPipe();

    if (INVALID_HANDLE_VALUE == hPipe)
    {
        goto cleanup;
    }

    bRet = WriteFile(hPipe, &cmdMsg, sizeof(cmdMsg), &dwBytesWritten, 0);

    if (!bRet || (sizeof(cmdMsg) != dwBytesWritten))
    {
        debug_print("Error sending command message, last error: %d\n", GetLastError());
        goto cleanup;
    }

    bRet = WriteFile(hPipe, pBuffer, imageSize, &dwBytesWritten, 0);

    if (!bRet || (imageSize != dwBytesWritten))
    {
        debug_print("Error sending MZ, last error: %d\n", GetLastError());
        goto cleanup;
    }

    bRet = ReadFile(hPipe, &iBuf, sizeof(iBuf), &dwBytesRead, 0);

    if (!bRet || (sizeof(iBuf) != dwBytesRead))
    {
        debug_print("Error receiving action, last error: %d\n", GetLastError());
        goto cleanup;
    }

    if (iBuf == 0)
    {
        allowLoad = false;
    }

cleanup:
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe);
    }

    return allowLoad;
}
