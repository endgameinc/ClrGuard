#include <windows.h>
#include <stdio.h>
#include "ClrHook.h"
#include "hook.h"
#include "pipe.h"

HookInfo g_imageLoadHook2;
HookInfo g_imageLoadHook4;

void * FindData(void * startAddr, DWORD memSize, char * targetStr, DWORD targetSize)
{
    size_t i = 0;

    for (DWORD_PTR addr = (DWORD_PTR)startAddr; addr < (DWORD_PTR)startAddr + memSize; addr++)
    {
        if (*(char*)addr == targetStr[i])
        {
            if (i == targetSize - 1)
            {
                return (void*)(addr - targetSize + 1);
            }
            i++;
        }
        else
        {
            i = 0;
        }
    }

    return 0;
}

//
// Hook used for native LoadImage in mscorwks.dll
//
#ifdef _WIN64
void *
#else
void * __fastcall
#endif
MyLoadImage2(U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void* securityUNSAFE,
    void* stackMark,
    BOOL fForIntrospection)
{
    DWORD bufSize = 0;
    void * retVal = 0;
    bool allowLoad = true;
    _LoadImage2 pOldLoadImage = (_LoadImage2)g_imageLoadHook2.pOldFunction;

    debug_print("Loading image of size: %p\n", (void*)PEByteArrayUNSAFE->bufferSize);
    debug_print("Header: %s\n", (char*)PEByteArrayUNSAFE->buffer);

    allowLoad = ReportLoadImage(PEByteArrayUNSAFE->buffer, (DWORD)PEByteArrayUNSAFE->bufferSize);

    if (!allowLoad)
    {
        printf("***BLOCKED***\n");
        ExitProcess(-1);
    }

    retVal = pOldLoadImage(PEByteArrayUNSAFE, SymByteArrayUNSAFE, securityUNSAFE, stackMark, fForIntrospection);

    return retVal;
}

//
// Hook used for native LoadImage in clr.dll
//
#ifdef _WIN64
void *
#else
void * __fastcall
#endif
MyLoadImage4(U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void* securityUNSAFE,
    void* stackMark,
    void* fForIntrospection,
    void* securityContextSource)
{
    DWORD bufSize = 0;
    void * retVal = 0;
    bool allowLoad = true;
    _LoadImage4 pOldLoadImage = (_LoadImage4)g_imageLoadHook4.pOldFunction;

    debug_print("Loading image of size: %p\n", (void*)PEByteArrayUNSAFE->bufferSize);
    debug_print("Header: %s\n", (char*)PEByteArrayUNSAFE->buffer);

    allowLoad = ReportLoadImage(PEByteArrayUNSAFE->buffer, (DWORD)PEByteArrayUNSAFE->bufferSize);

    if (!allowLoad)
    {
        printf("***BLOCKED***\n");
        ExitProcess(-1);
    }

    retVal = pOldLoadImage(PEByteArrayUNSAFE, SymByteArrayUNSAFE, securityUNSAFE, stackMark, fForIntrospection, securityContextSource);

    return retVal;
    
}

void _AllocConsole()
{
    AllocConsole();
    FILE* pCout;
    freopen_s(&pCout, "conout$", "w", stdout); //returns 0
    SetConsoleTitle(L"ClrHook");
}

// Locate the native LoadImage() function. This is a bit
// Hackerman has worked on all versions tested.
void * LocateAssemblyLoad(void * imageBase, DWORD imageSize)
{
    void * nLoadImage = FindData(imageBase, imageSize, "nLoadImage", (DWORD)strlen("nLoadImage"));

    if (nLoadImage == 0)
    {
        debug_print("nLoadImage not found\n");
        return 0;
    }

    debug_print("nLoadImage found at: %p\n", nLoadImage);

    void * pMapping = FindData(imageBase, imageSize, (char*)&nLoadImage, sizeof(DWORD_PTR));

    if (pMapping == 0)
    {
        debug_print("pMapping not found\n");
        return 0;
    }

    debug_print("pMapping found at: %p\n", pMapping);

    void * pImageLoad = *(void**)((DWORD_PTR)pMapping - sizeof(DWORD_PTR));

    debug_print("pImageLoad found at: %p\n", pImageLoad);

    return pImageLoad;
}


//
// Monitor for DLL Load events so we can hook the CLR dll once it is
// loaded.
//
VOID CALLBACK LdrDllNotification(
    _In_     ULONG                       NotificationReason,
    _In_     PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID                       Context
)
{
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        if (_wcsicmp(NotificationData->Loaded.BaseDllName->Buffer, L"mscorwks.dll") == 0)
        {
#ifdef _DEBUG
            _AllocConsole();
#endif
            // Add Hook
            debug_print("Loaded %ws\n", NotificationData->Loaded.BaseDllName->Buffer);

            void * pImageLoad = LocateAssemblyLoad(NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);

            if (pImageLoad)
            {
                g_imageLoadHook2.pTargetFunction = pImageLoad;
                g_imageLoadHook2.pNewFunction = MyLoadImage2;
                InstallHook(&g_imageLoadHook2);
            }
        }
        else if (_wcsicmp(NotificationData->Loaded.BaseDllName->Buffer, L"clr.dll") == 0)
        {
#ifdef _DEBUG
            _AllocConsole();
#endif
            // Add Hook
            debug_print("Loaded %ws\n", NotificationData->Loaded.BaseDllName->Buffer);

            void * pImageLoad = LocateAssemblyLoad(NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);
            
            if (pImageLoad)
            {
                g_imageLoadHook4.pTargetFunction = pImageLoad;
                g_imageLoadHook4.pNewFunction = MyLoadImage4;
                InstallHook(&g_imageLoadHook4);
            }
        }
       
    }

}

