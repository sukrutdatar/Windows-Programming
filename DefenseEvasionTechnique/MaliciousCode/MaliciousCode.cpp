#include <iostream>

int main()
{
	system("echo Executed malicious code successfully!! > malicious.txt");
	system("notepad.exe malicious.txt");

	std::cout << std::endl << std::endl;
	return 0;
}