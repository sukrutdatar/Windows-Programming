#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include "..\Arithmatic\Arithmatic.h"
#pragma comment(lib, "../Release/Arithmatic.lib")

#define BUFSIZE 1024
#define MD5LEN 32
#define HASH "AD5CAD32FDB39499110A57E32667AAD4"

BOOL Authenticate()
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdefghijklmnopqrstuv";
	LPCWSTR fileName = L"Arithmatic.dll";

	hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			{
				while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
				{
					if (0 == cbRead)
						break;
					if (!CryptHashData(hHash, rgbFile, cbRead, 0))
					{
						std::cout << std::endl << "HashData failed";
						return FALSE;
					}
				}
				cbHash = MD5LEN;
				if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
				{
					std::cout << std::endl;
					for (DWORD i = 0; i < cbHash; i++)
					{
						printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i & 0x1f]] );
					}

				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hProv, 0);	
		}
		CloseHandle(hFile);
	}
	return FALSE;
}


int main()
{

	if (!Authenticate())
		return 0;

	int a = 10;
	int b = 20;
	std::cout << std::endl << "maximum(" << a << ", " << b << ") = " << maximum(a, b);

	HMODULE hArithmaticModule = LoadLibrary(TEXT("Arithmatic.dll"));
	if (hArithmaticModule != NULL)
	{
		typedef int (*Add)(int, int); 
		Add add = (Add)GetProcAddress(hArithmaticModule, "add");
		if (add)
			std::cout << std::endl << "add(" << a << ", " << b << ") = " << add(a, b);
	}

	std::cout << std::endl << std::endl;
	return 0;
}
