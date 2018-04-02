#include <windows.h>
#include <stdio.h>
#include "ClrHook.h"
#include "hook.h"
#include "pipe.h"

HookInfo g_imageLoadHook2;
HookInfo g_imageLoadHook4;
HookInfo g_loadModuleHook4;
HookInfo g_loadModuleHook2;

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
// Hook used for native LoadModule in mscorwks.dll
//
#ifdef _WIN64
void *
#else
void * __stdcall
#endif
MyLoadModule2(void * pAssembly,
    void * ModuleName,
    U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void * module)
{
    DWORD bufSize = 0;
    void * retVal = 0;
    bool allowLoad = true;
    _LoadModule2 pOldLoadModule = (_LoadModule2)g_loadModuleHook2.pOldFunction;

    debug_print("Loading image of size: %p\n", (void*)PEByteArrayUNSAFE->bufferSize);
    debug_print("Header: %s\n", (char*)PEByteArrayUNSAFE->buffer);

    allowLoad = ReportLoadImage(PEByteArrayUNSAFE->buffer, (DWORD)PEByteArrayUNSAFE->bufferSize);

    if (!allowLoad)
    {
        printf("***BLOCKED***\n");
        ExitProcess(-1);
    }

    retVal = pOldLoadModule(pAssembly, ModuleName, PEByteArrayUNSAFE, SymByteArrayUNSAFE, module);

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

//
// Hook used for native LoadModule in clr.dll
//
#ifdef _WIN64
void *
#else
void * __fastcall
#endif
MyLoadModule4(void * pAssembly,
    LPCWSTR wszModuleName,
    LPCBYTE pRawModule,
    INT32 cbModule,
    LPCBYTE pRawSymbolStore,
    INT32 cbSymbolStore,
    void * retModule)
{
    DWORD bufSize = 0;
    void * retVal = 0;
    bool allowLoad = true;
    _LoadModule4 pOldLoadModule = (_LoadModule4)g_loadModuleHook4.pOldFunction;

    debug_print("Loading image of size: %lx\n", cbModule);
    debug_print("Header: %s\n", (char*)pRawModule);

    allowLoad = ReportLoadImage((void*)pRawModule, (DWORD)cbModule);

    if (!allowLoad)
    {
        printf("***BLOCKED***\n");
        ExitProcess(-1);
    }

    retVal = pOldLoadModule(pAssembly, wszModuleName, pRawModule, cbModule, pRawSymbolStore, cbSymbolStore, retModule);

    return retVal;

}


void _AllocConsole()
{
    AllocConsole();
    FILE* pCout;
    freopen_s(&pCout, "conout$", "w", stdout); //returns 0
    SetConsoleTitle(L"ClrHook");
}

// Locate the native LoadImage/LoadModule function. This is a bit
// Hackerman has worked on all versions tested.
void * LocateFunctionByName(char * funcName, void * imageBase, DWORD imageSize)
{
    void * pFuncName = FindData(imageBase, imageSize, funcName, (DWORD)strlen(funcName));

    if (pFuncName == 0)
    {
        debug_print("%s not found\n", funcName);
        return 0;
    }

    debug_print("%s found at: %p\n", funcName, pFuncName);

    void * pMapping = FindData(imageBase, imageSize, (char*)&pFuncName, sizeof(DWORD_PTR));

    if (pMapping == 0)
    {
        debug_print("pMapping not found\n");
        return 0;
    }

    debug_print("pMapping found at: %p\n", pMapping);

    void * pFuncAddr = *(void**)((DWORD_PTR)pMapping - sizeof(DWORD_PTR));

    debug_print("%s found at: %p\n", funcName, pFuncAddr);

    return pFuncAddr;
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

            void * pImageLoad = LocateFunctionByName("nLoadImage", NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);

            if (pImageLoad)
            {
                g_imageLoadHook2.pTargetFunction = pImageLoad;
                g_imageLoadHook2.pNewFunction = MyLoadImage2;
                InstallHook(&g_imageLoadHook2);
            }

            void * pLoadModule = LocateFunctionByName("_nLoadModule", NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);

            if (pLoadModule)
            {
                g_loadModuleHook2.pTargetFunction = pLoadModule;
                g_loadModuleHook2.pNewFunction = MyLoadModule2;
                InstallHook(&g_loadModuleHook2);
            }

        }
        else if (_wcsicmp(NotificationData->Loaded.BaseDllName->Buffer, L"clr.dll") == 0)
        {
#ifdef _DEBUG
            _AllocConsole();
#endif
            // Add Hook
            debug_print("Loaded %ws\n", NotificationData->Loaded.BaseDllName->Buffer);

            void * pImageLoad = LocateFunctionByName("nLoadImage", NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);

            if (pImageLoad)
            {
                g_imageLoadHook4.pTargetFunction = pImageLoad;
                g_imageLoadHook4.pNewFunction = MyLoadImage4;
                InstallHook(&g_imageLoadHook4);
            }

            void * pLoadModule = LocateFunctionByName("LoadModule", NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage);

            if (pLoadModule)
            {
                g_loadModuleHook4.pTargetFunction = pLoadModule;
                g_loadModuleHook4.pNewFunction = MyLoadModule4;
                InstallHook(&g_loadModuleHook4);
            }

        }

    }

}

