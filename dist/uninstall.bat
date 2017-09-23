reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs  /t REG_DWORD /f /d 0
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs  /t /f REG_DWORD /d 0

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /f /d ""
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /f /d ""

del c:\windows\system32\ClrHook64.dll
del c:\windows\syswow64\ClrHook32.dll
