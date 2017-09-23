#include <windows.h>

typedef struct  {
    void * pTargetFunction;
    void * pNewFunction;
    void * pOldFunction;

} HookInfo;

void InstallHook(HookInfo * hookInfo);



