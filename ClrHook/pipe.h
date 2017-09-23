#pragma once
#include <windows.h>

#define PIPE_NAME "\\\\.\\pipe\\ClrGuard"

typedef struct
{
    DWORD pid;
    DWORD msgSize;
} CMD_MSG;

bool ReportLoadImage(void * pBuffer, DWORD imageSize);
