#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winbase.h>
#include <iostream>
#include <fileapi.h>
#include <Tlhelp32.h>
#include <comdef.h>

int getPID(){
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, "ScrapMechanic.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                CloseHandle(hProcess);

                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);

    return -1;
}

int main() {

  DWORD PID = getPID();
  if(PID == -1){
    std::cout << "\033[0;31mOpenProcess Failed: game not found" << "\033[0m" << std::endl;
    return -1;
  }//return 0;
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	char name[1000];
	GetModuleBaseNameA(process, NULL, (LPSTR) name, 1000);
	printf( "\nInjecting into: %s\n", name );

  if (!process){
      std::cout << "\033[0;31mOpenProcess Failed: " << GetLastError() <<  "\033[0m" << std::endl;
      return -1;
  }

  char dll_fullPath[MAX_PATH];
  const char* dll_name = "main.dll";
  GetFullPathNameA(dll_name, MAX_PATH, dll_fullPath, NULL);

  DWORD dWord;
  LPTHREAD_START_ROUTINE load_library = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibraryA("kernel32"), "LoadLibraryA");
  LPVOID remote_str = VirtualAllocEx(process, NULL, strlen(dll_fullPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  WriteProcessMemory(process, remote_str, dll_fullPath, strlen(dll_fullPath), NULL);
  CreateRemoteThread(process, NULL, NULL, load_library, remote_str, NULL, NULL);

  return 0;
}
