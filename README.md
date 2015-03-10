# WinCodeInjection

This repository contains 2 samples:
* Dll Injector with a Dll to inject
* Code Injector

The Dll Injector sample use the undocumented function *NtCreateThreadEx* to launch a remote thread. 
If you want to use *CreateRemoteThread*, you have to remember that starting with Win Vista (Session Separation) 
a process situated in a session can't access to a process in a different session.

The Code injector performs a change on the *image relocation table* to adjust it to the new base. In this sample I use the
simple *CreateRemoteThread* to insert a custom function in another process.
