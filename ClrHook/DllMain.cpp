#include <Windows.h>
#include <stdio.h>
#include "ClrHook.h"

void ProcessSetup()
{
    // Setup our DLL load callback
    _LdrRegisterDllNotification LdrRegisterDllNotification = 
        (_LdrRegisterDllNotification)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrRegisterDllNotification");
    if (LdrRegisterDllNotification)
    {
        void * cookie;
        LdrRegisterDllNotification(0, LdrDllNotification, 0, &cookie);
    }

}
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ProcessSetup();
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return true;

}

