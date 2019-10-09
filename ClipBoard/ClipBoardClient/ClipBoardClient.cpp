#include <Windows.h>
#include <stdio.h>

int main()
{
	char* data = NULL;
	char* globalMemory = NULL;
	HWND hwndClipboard = NULL;
	HANDLE hMemory;

	if (OpenClipboard(hwndClipboard))
	{
		hMemory = GetClipboardData(CF_TEXT);
		if (hMemory == NULL)
		{
			printf("\nCould not get clipboard data.");
		}
		else
		{
			globalMemory = (char*)GlobalLock(hMemory);
			if (globalMemory == NULL)
			{
				printf("\nFailed to lock global memory.");
			}
			else
			{
				data = (char*)malloc(GlobalSize(hMemory));
				if (data == NULL)
				{
					printf("\nFailed to allocate memory for local buffer.");
				}
				else
				{
					memcpy(data, globalMemory, GlobalSize(hMemory));
					printf("\nData from clipboard is: %s", data);
					free(data);
				}
				GlobalUnlock(hMemory);
			}
		}
		CloseClipboard();
	}

	printf("\n\n");
	return 0;
}
