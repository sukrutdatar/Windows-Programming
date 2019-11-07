#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

#include "..\Arithmatic\Arithmatic.h"
#include "openssl\include\openssl\sha.h"

#pragma comment(lib, "../Release/Arithmatic.lib")

#define SHA256 "651618d94d75571f8abd2a480c6368e124a0542a2bc0e6a10be7ca6e455570e9"

BOOL Authenticate()
{
	ifstream istream("Arithmatic.dll", std::ios::in | std::ios::binary);
	
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


int main()
{

	if (!Authenticate())
	{
		cout << endl << "Malicious DLL found, load dll fail.";
		return 0;
	}
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
