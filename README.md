# ClrGuard
ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.

To jump in and play with ClrGuard, you can copy the dist\ folder to a virtual machine and run the install.bat script. Next, start the ClrGuard.exe process to complete the installation. The default block action is hard-coded in ClrGuard.h. You could also specific the "-i" parameter to install ClrGuard.exe as a service. 

It is not recommended to run this tool in a production environment. 