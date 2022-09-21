#include <stdio.h>
#include <Windows.h>
#include <psapi.h>
#include <winbase.h>
#include <string.h>

int main() {

	DWORD PID;
	char DLL_Path[200];

	printf( "Enter a PID:");
	scanf("%d", &PID );

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	char name[1000];
	GetModuleBaseNameA(hProc, NULL, (LPSTR) name, 1000);
	printf( "\nYou entered: %s\n", name );

	printf("DLL name (name.dll):");
	int DLL_size = scanf("%s", &DLL_Path);

	if (hProc == NULL){
		printf( "\033[31m\nYou entered: %d, moron\033[0m", PID);
		return -1;
	}else{
		char DLL_fullPath[1000];
		int DLL_fullSize = GetCurrentDirectoryA(1000, DLL_fullPath);

		strcpy(DLL_fullPath + DLL_fullSize, "\\");
		strcpy(DLL_fullPath + DLL_fullSize + 1, DLL_Path);

		LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, strlen(DLL_fullPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE); //MEM_COMMIT, PAGE_EXECUTE_READWRITE are defaulted

		printf( "??? %d ???\n", strlen(DLL_fullPath) );
		printf( "!!! %s !!!\n", DLL_fullPath );

		if (MyAlloc == NULL){
			printf( "\033[31mFaild to allocate memory in Target Process.\n\033[0m" );
			return -1;
		}

		printf( "Allocated memory in Target Process.\n" );

		int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, DLL_fullPath, strlen(DLL_fullPath), 0);

		if (IsWriteOK == 0){
			printf("\033[31mFail to write in Target Process memory.\n\033[0m");
			return -1;
		}

		DWORD dWord;
		LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibraryA("kernel32"), "LoadLibraryA");

		HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
		if (ThreadReturn == NULL){
			printf("\033[31mFail to create Remote Thread.\n\033[0m");
			return -1;
		}

		printf("\033[1m\033[32mDLL Successfully Injected \033[33m:)\n\033[0m");

	}

	return 0;
};
