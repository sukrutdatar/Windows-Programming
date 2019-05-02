#include <Windows.h>
#include <iostream>
#include "../ArithmeticLibrary/Arithmetic.h"

#pragma comment (lib, "ArithmeticLibrary")

int main()
{
	int a, b, ans;

	std::cout << std::endl << "Enter number one: ";
	std::cin >> a;

	std::cout << std::endl << "Enter number two: ";
	std::cin >> b;


	ans = Add(a, b);
	std::cout << std::endl << "Addition of (" << a << ", " << b << ") = " << ans;

	ans = Subtract(a, b);
	std::cout << std::endl << "Subraction of (" << a << ", " << b << ") = " << ans;

	ans = Multiply(a, b);
	std::cout << std::endl << "Multiplication of (" << a << ", " << b << ") = " << ans;

	std::cout << std::endl << std::endl;
	return 0;
}