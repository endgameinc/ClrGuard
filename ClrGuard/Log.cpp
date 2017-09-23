#include "ClrGuard.h"

// 
// Logs the event to the file specified in the LOG_FILE
// define in ClrGuard.h
//
void LogEvent(DWORD pid, wchar_t *processPath, char * moduleHash, char * fuzzyHash, DWORD action)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    SYSTEMTIME sysTime;
    char szBuf[512];
    wchar_t stDate[32];
    wchar_t stTime[32];
    DWORD dwWritten = 0;

    GetDateFormat(LOCALE_USER_DEFAULT, 0, 0, NULL, stDate, _countof(stDate));
    GetTimeFormat(LOCALE_USER_DEFAULT, TIME_FORCE24HOURFORMAT, 0, NULL, stTime, _countof(stTime));

    GetLocalTime(&sysTime);

    sprintf_s(szBuf, _countof(szBuf), 
        "%ws %ws, PID: %d, Path: %ws, Module Hash: %hs, Fuzzy Hash: %hs, Action: %d\r\n", 
        stDate, stTime, pid, processPath, moduleHash, fuzzyHash, action);

    hFile = CreateFile(LOG_FILE, FILE_APPEND_DATA, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening log file: %d\n", GetLastError());
    }

    WriteFile(hFile, szBuf, (DWORD)strlen(szBuf), &dwWritten, 0);

    CloseHandle(hFile);
}

