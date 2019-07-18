#include "pch.h"
#include <iostream>

void Attack();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Attack();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void Attack() 
{
	system("echo Injection and execution success!! > C:\\injection.txt");
	system("notepad.exe C:\\injection.txt");
}