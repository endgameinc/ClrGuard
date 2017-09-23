#include <Windows.h>
#include "hook.h"
#include "distorm\distorm.h"

#ifdef _WIN64
#pragma comment(lib,"distorm\\distorm64.lib")
#else
#pragma comment(lib,"distorm\\distorm32.lib")
#endif


#ifdef _WIN64
void InstallHook(HookInfo * hookInfo)
{
    DWORD dwOld;
    LPVOID trampAddr = NULL;
    int trampSize = 0;

    // allocate tramp buffer
    trampAddr = VirtualAlloc(0, 37, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    unsigned __int64 trampAddrInt = (unsigned __int64)trampAddr;

    memset(trampAddr, '\x90', 37);

    // find target function
    PVOID targetFunc = hookInfo->pTargetFunction;

    if (targetFunc == 0)
        return;

    // distorm code
    // How many instructions to allocate on stack.
#define MAX_INSTRUCTIONS 32
    // Holds the result of the decoding.
    _DecodeResult res;
    // Default offset for buffer is 0.
    _OffsetType offset = 0;
    // Decoded instruction information - the Decode will write the results here.
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    // decodedInstructionsCount indicates how many instructions were written to the result array.
    unsigned int decodedInstructionsCount = 0;
    // Default decoding mode is 32 bits.
    _DecodeType dt = Decode64Bits;

    // Decode the buffer at given offset (virtual address).
    res = distorm_decode(offset, (const unsigned char*)targetFunc, 32, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    if (res == DECRES_INPUTERR)
        return;

    unsigned int totalSize = 0;

    for (unsigned int x = 0; x < decodedInstructionsCount; x++)
    {
        if (totalSize >= 12)
            break;
        totalSize += decodedInstructions[x].size;
    }
    // end distorm code
    //log("Total size of tramp: %d", totalSize);
    trampSize = totalSize;

    hookInfo->pOldFunction = (void*)trampAddr;

    unsigned __int64 targetFuncInt = (unsigned __int64)targetFunc;

    // Copy first x bytes of function to tramp
    memcpy(trampAddr, targetFunc, totalSize);
    // Create a jump to original function+totalSize from tramp
    trampAddrInt += totalSize;

    // 68 <00 00 00 00>             push <low dword>
    // C7 44 24 04 <00 00 00 00>    mov [rsp+4], <high dword>
    // C3

    DWORD dwLow = (DWORD)targetFuncInt + totalSize;
    DWORD dwHigh = (DWORD)((targetFuncInt +totalSize)>> 32);

    memcpy((PVOID)trampAddrInt, "\x68", 1);
    trampAddrInt += 1;

    memcpy((PVOID)trampAddrInt, &dwLow, 4);
    trampAddrInt += 4;

    memcpy((PVOID)trampAddrInt, "\xC7\x44\x24\x04", 4);
    trampAddrInt += 4;

    memcpy((PVOID)trampAddrInt, &dwHigh, 4);
    trampAddrInt += 4;

    memcpy((PVOID)trampAddrInt, "\xC3", 1);
    trampAddrInt += 1;
    // Trampoline has been constructed

    // Reset pointer
    targetFuncInt = (unsigned __int64)targetFunc;

    // Set target function writeable, should probably set its old permissions for stealth
    VirtualProtect((LPVOID)targetFunc, 37, PAGE_EXECUTE_READWRITE, &dwOld);

    // Intercept target function, send all calls to my function
    unsigned __int64 myFuncInt = (unsigned __int64)hookInfo->pNewFunction;
    memcpy((PVOID)targetFuncInt, "\x48\xb8", 2);
    targetFuncInt += 2;
    memcpy((PVOID)targetFuncInt, &myFuncInt, 8);
    targetFuncInt += 8;
    memcpy((PVOID)targetFuncInt, "\xff\xe0", 2);
    targetFuncInt += 2;


    // Fix memory protection for hooked function
    VirtualProtect((LPVOID)targetFunc, 37, dwOld, &dwOld);

    // Hooking is now complete

}
#else

void InstallHook(HookInfo * hookInfo)
{
    DWORD dwOld;
    LPVOID trampAddr = NULL;
    int trampSize = 0;

    // Allocate tramp buffer
    trampAddr = VirtualAlloc(0, 37, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    DWORD trampAddrPtr = (DWORD)trampAddr;

    memset(trampAddr, '\x90', 37);

    // Find target function
    PVOID targetFunc = hookInfo->pTargetFunction;

    if (targetFunc == 0)
        return;

    // distorm code
    // How many instructions to allocate on stack.
#define MAX_INSTRUCTIONS 32
    // Holds the result of the decoding.
    _DecodeResult res;
    // Default offset for buffer is 0.
    _OffsetType offset = 0;
    // Decoded instruction information - the Decode will write the results here.
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    // decodedInstructionsCount indicates how many instructions were written to the result array.
    unsigned int decodedInstructionsCount = 0;
    // Default decoding mode is 32 bits.
    _DecodeType dt = Decode32Bits;

    // Decode the buffer at given offset (virtual address).
    res = distorm_decode(offset, (const unsigned char*)targetFunc, 32, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    if (res == DECRES_INPUTERR)
        return;

    unsigned int totalSize = 0;

    for (unsigned int x = 0; x < decodedInstructionsCount; x++)
    {
        if (totalSize >= 5)
            break;
        totalSize += decodedInstructions[x].size;
    }
    // end distorm code

    trampSize = totalSize;

    hookInfo->pOldFunction = (void*)trampAddr;

    DWORD targetFuncPtr = (DWORD)targetFunc;

    ULONG bytes = 20;
    // Set target function writeable
    VirtualProtect((LPVOID)targetFunc, 37, PAGE_EXECUTE_READWRITE, &dwOld);

    // Copy instructions of function to tramp
    memcpy(trampAddr, targetFunc, totalSize);
    // Create a jump to original function+5 from tramp
    trampAddrPtr += totalSize;
    memcpy((PVOID)trampAddrPtr, "\xe9", 1);
    // offset = destination - address of e9 - 5
    int myOffset = (int)targetFuncPtr + totalSize - (int)trampAddrPtr - 5;
    trampAddrPtr += 1;
    memcpy((PVOID)trampAddrPtr, &myOffset, 4);
    // Trampoline has been constructed

    // Reset pointer
    targetFuncPtr = (DWORD)targetFunc;

    // Intercept target function, send all calls to my function
    DWORD myFuncPtr = (DWORD)hookInfo->pNewFunction;
    memcpy((PVOID)targetFuncPtr, "\xe9", 1);
    // offset = destination - address of e9 - 5
    myOffset = (int)myFuncPtr - (int)targetFuncPtr - 5;
    targetFuncPtr += 1;
    memcpy((PVOID)targetFuncPtr, &myOffset, 4);

    // Fix memory protection for hooked function
    VirtualProtect((LPVOID)targetFunc, 37, dwOld, &dwOld);

}
#endif
