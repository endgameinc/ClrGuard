#include <windows.h>
#include <stdio.h>

void ReflectionLoad(wchar_t * filePath, int version);

int main()
{

    HMODULE hClrHook = LoadLibrary(L"ClrHook.dll");

    /*
#ifdef _WIN64
    HMODULE hClr = LoadLibrary(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll");
#else
    HMODULE hClr = LoadLibrary(L"C:\Windows\Microsoft.NET\Framework\v4.0.30319");
#endif
*/
    ReflectionLoad(L"InjectExample.exe", 4);

    return 0;
}