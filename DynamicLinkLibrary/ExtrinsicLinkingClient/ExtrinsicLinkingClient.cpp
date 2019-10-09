#include <Windows.h>
#include <iostream>
#include "../ArithmeticLibrary/Arithmetic.h"

int main()
{
	HMODULE hArithmeticLibModule;
	int a, b, ans;

	std::cout << std::endl << "Enter number one: ";
	std::cin >> a;

	std::cout << std::endl << "Enter number two: ";
	std::cin >> b;

	hArithmeticLibModule = LoadLibrary(L"ArithmeticLibrary.dll");

	if (hArithmeticLibModule != NULL)
	{
		int(*additionFptr) (int, int) = (int(*) (int, int)) GetProcAddress(hArithmeticLibModule, "Add");
		if (additionFptr)
		{
			ans = additionFptr(a, b);
			std::cout << std::endl << "Addition of (" << a << ", " << b << ") = " << ans;
		}
		else
			std::cout << std::endl << "Failed to get address of method: Add";

		int(*subractionFptr) (int, int) = (int(*) (int, int)) GetProcAddress(hArithmeticLibModule, "Subtract");
		if (subractionFptr)
		{
			ans = subractionFptr(a, b);
			std::cout << std::endl << "Subraction of (" << a << ", " << b << ") = " << ans;
		}
		else
			std::cout << std::endl << "Failed to get address of method: Subtract";

		int(*multiplicationFptr) (int, int) = (int(*) (int, int)) GetProcAddress(hArithmeticLibModule, "Multiply");
		if (multiplicationFptr)
		{
			ans = multiplicationFptr(a, b);
			std::cout << std::endl << "Multiplication of (" << a << ", " << b << ") = " << ans;
		}
		else
			std::cout << std::endl << "Failed to get address of method: Multiply";

		if (!FreeLibrary(hArithmeticLibModule))
			std::cout << std::endl << "Failed to unload module!";
	}
	else
	{
		std::cout << std::endl << "Loading of library failed!";
	}

	std::cout << std::endl << std::endl;
	return 0;
}
