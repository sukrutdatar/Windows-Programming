#include <Windows.h>
#include <atlstr.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

#include "..\Arithmatic\Arithmatic.h"
#include "openssl\include\openssl\sha.h"

#pragma comment(lib, "../Release/Arithmatic.lib")

#define DLL_NAME "Arithmatic.dll"
#define SHA256 "651618d94d75571f8abd2a480c6368e124a0542a2bc0e6a10be7ca6e455570e9"

std::string GetModulePath()
{
	HMODULE hArithmaticModule = LoadLibraryEx(TEXT(DLL_NAME), NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hArithmaticModule)
	{
		TCHAR dllPath[_MAX_PATH];
		HMODULE hModule = GetModuleHandle(TEXT(DLL_NAME));
		if (hModule)
		{
			GetModuleFileName(hModule, dllPath, _MAX_PATH);
			FreeLibrary(hArithmaticModule);
			std::wstring path = std::wstring(dllPath);
			return std::string(path.begin(), path.end());
		}
	}
	return "";
}


BOOL Authenticate(std::string* safeLoadPath)
{
	safeLoadPath = new std::string(GetModulePath());
	ifstream istream(safeLoadPath->c_str(), std::ios::in | std::ios::binary);
	
	std::string content = std::string((std::istreambuf_iterator<char>(istream)), (std::istreambuf_iterator<char>()));
	istream.close();
	
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, content.c_str(), content.size());
	SHA256_Final(digest, &ctx);

	stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)digest[i];
	}


	if (std::string(ss.str()) == SHA256)
		return TRUE;

	return FALSE;
}


int main(int argc, char** argv)
{
	bool safeLoad = false;
	std::string* safeLoadPath = new std::string(DLL_NAME);
	if (argc == 2)
	{
		std::string argument(argv[1]);
		if (argument == "-safe")
			safeLoad = true;
	}

	if (safeLoad)
	{
		if (!Authenticate(safeLoadPath))
		{
			cout << endl << "Malicious DLL found, load dll fail.";
			return 0;
		}
	}

	int a = 10;
	int b = 20;
	

	HMODULE hArithmaticModule = LoadLibrary(std::wstring(safeLoadPath->begin(), safeLoadPath->end()).c_str());
	if (hArithmaticModule != NULL)
	{
		typedef int (*Arithmatic)(int, int); 
		Arithmatic add = (Arithmatic)GetProcAddress(hArithmaticModule, "add");
		if (add)
			std::cout << std::endl << "add(" << a << ", " << b << ") = " << add(a, b);

		Arithmatic maximum = (Arithmatic)GetProcAddress(hArithmaticModule, "maximum");
		if (maximum)
		std::cout << std::endl << "maximum(" << a << ", " << b << ") = " << maximum(a, b);

		FreeLibrary(hArithmaticModule);
	}

	std::cout << std::endl << std::endl;
	return 0;
}
