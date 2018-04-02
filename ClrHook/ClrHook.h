#pragma once
#include <Windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2);

typedef LONG NTSTATUS;

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000)

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef NTSTATUS(NTAPI * _LdrRegisterDllNotification) (
    _In_     ULONG                          Flags,
    _In_     PVOID                          NotificationFunction,
    _In_opt_ PVOID                          Context,
    _Out_    PVOID                          *Cookie
    );

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1


VOID CALLBACK LdrDllNotification(
    _In_     ULONG                       NotificationReason,
    _In_     PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID                       Context
);

typedef struct _U1Array {
    void * vtbl;
    size_t bufferSize;
    char buffer[1];
} U1Array;

#ifdef _WIN64
typedef void*(*_LoadImage2)(
#else
typedef void*(__fastcall*_LoadImage2)(
#endif
    U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void* securityUNSAFE,
    void* stackMark,
    BOOL fForIntrospection);

#ifdef _WIN64
typedef void*(*_LoadImage4)(
#else
typedef void*(__fastcall*_LoadImage4)(
#endif
    U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void* securityUNSAFE,
    void* stackMark,
    void* fForIntrospection,
    void* securityContextSource);

#ifdef _WIN64
typedef void*(*_LoadModule4)(
#else
typedef void*(__fastcall*_LoadModule4)(
#endif
    void * pAssembly,
    LPCWSTR wszModuleName,
    LPCBYTE pRawModule,
    INT32 cbModule,
    LPCBYTE pRawSymbolStore,
    INT32 cbSymbolStore,
    void * retModule);

#ifdef _WIN64
typedef void*(*_LoadModule2)(
#else
typedef void*(__fastcall*_LoadModule2)(
#endif
    void * pAssembly,
    void * ModuleName,
    U1Array* PEByteArrayUNSAFE,
    U1Array* SymByteArrayUNSAFE,
    void * module);

