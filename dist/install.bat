copy /y ClrHook64.dll c:\windows\system32\ClrHook64.dll
copy /y ClrHook32.dll c:\windows\syswow64\ClrHook32.dll


reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs  /t REG_DWORD /f /d 0x1
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs  /t /f REG_DWORD /d 0x1

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /f /d ClrHook64.dll
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /f /d ClrHook32.dll



