#include <Windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("\n\nMissing parameter <data>");
		printf("\nUsage: ClipBoardServer.exe <data>");
	}
	else
	{
		char* globalMemory;
		HGLOBAL hGlobalMemory;
		size_t inputLength;
		HWND hwndClipboard = NULL;

		inputLength = strlen(argv[1]);

		hGlobalMemory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, inputLength + 1);

		if (hGlobalMemory == NULL)
		{
			printf("\nFailed to allocated memory.");
		}
		else
		{
			globalMemory = (char *)GlobalLock(hGlobalMemory);

			if (globalMemory == NULL)
			{
				printf("\nFailed to lock global memory.");
			}

			memcpy(globalMemory, argv[1], inputLength);

			if (OpenClipboard(hwndClipboard))
			{
				EmptyClipboard();
				SetClipboardData(CF_TEXT, hGlobalMemory);
				CloseClipboard();
			}
			GlobalFree(hGlobalMemory);
		}
	}
	printf("\n\n");
	return 0;
}
