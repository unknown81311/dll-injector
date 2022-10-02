#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <Psapi.h>
#include <iostream>
#include <process.h>
#include <stdio.h>
#include <cstdio>
#include "steam/steam_api.h"
#include <utility>
#include "sigscan.h"
#include <limits>
#include <cassert>
#include <iostream>
#include <tchar.h>
#include <psapi.h>
#include <chrono>
#include <thread>
#include <fstream>
#include <winuser.h>

using namespace std;
using std::string;

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

void bypassDev(HANDLE con_handle) {

	SignatureScanner sigScanner(L"ScrapMechanic.exe");
	if (!sigScanner.readMemory()) {
    WriteConsole(con_handle, "failed to find dev flag\n", 21, NULL, NULL);
		return;
	}

	DWORD64 compare_flag = sigScanner.scan("\x38\x43\x78\x0f\x85\xa2\x0a\x00\x00", "xxxxx????");
	if (!compare_flag) {
    WriteConsole(con_handle, "failed to find dev flag\n", 21, NULL, NULL);
		return;
	}

  string line = "found dev flag " + std::to_string(compare_flag) + '\n';
  WriteConsole(con_handle, line.c_str(), line.size(), NULL, NULL);

	LPVOID dst = (LPVOID) compare_flag;
	size_t len = 9;
	DWORD oldProtection;
	DWORD temp;

	// Allow modifications of the target function
	VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProtection);

	// Replace the cmp and jne instructions with NOP
	memset((void *) compare_flag, 0x90, len);

	// Restore protection
	VirtualProtect(dst, len, oldProtection, &temp);


	return;
}

// void loadSettings(HANDLE con_handle){
//   DWORD processID = getPID();

//   HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
//                           PROCESS_VM_READ,
//                           FALSE, processID );

//   const char filePath[MAX_PATH];
//   GetModuleFileNameExW(hProcess, NULL, filePath, MAX_PATH);

//   WriteConsole(con_handle, filePath, strlen(filePath), NULL, NULL);

//   fstream my_file;
//   my_file.open("my_file", ios::out);
//   if (!my_file) {
//     cout << "File not created!";
//   }
//   else {
//     cout << "File created successfully!";
//     my_file.close(); 
//   }
// }

void writeUserData(HANDLE con_handle){
    SetConsoleTextAttribute(con_handle, FOREGROUND_RED);

    char logo[] = "  ██████▓██   ██▓▄▄▄█████▓ ██░ ██ ▓█████ \n▒██    ▒ ▒██  ██▒▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ \n░ ▓██▄    ▒██ ██░▒ ▓██░ ▒░▒██▀▀██░▒███   \n  ▒   ██▒ ░ ▐██▓░░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ \n▒██████▒▒ ░ ██▒▓░  ▒██▒ ░ ░▓█▒░██▓░▒████▒\n▒ ▒▓▒ ▒ ░  ██▒▒▒   ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░\n░ ░▒  ░ ░▓██ ░▒░     ░     ▒ ░▒░ ░ ░ ░  ░\n░  ░  ░  ▒ ▒ ░░    ░       ░  ░░ ░   ░   \n      ░  ░ ░               ░  ░  ░   ░  ░\n         ░ ░                             \nInjected into ScrapMechanic.exe\n";
    
    WriteConsole(con_handle, logo, strlen(logo), NULL, NULL);
    
    CSteamID steamID = SteamUser()->GetSteamID();
    const char * steamNAME = SteamFriends()->GetPersonaName();

    using std::string;

    string line1 = "username: " + string(steamNAME) + '\n';
    string line2 = "ID: " + std::to_string(steamID.ConvertToUint64()) + '\n';

    WriteConsole(con_handle, line1.c_str(), line1.size(), NULL, NULL);
    WriteConsole(con_handle, line2.c_str(), line2.size(), NULL, NULL);
}

DWORD WINAPI Main(HMODULE hModule){
  const HANDLE con_handle = GetStdHandle(STD_OUTPUT_HANDLE);

  //console logo and user data
  writeUserData(con_handle);

  //load settings
  // loadSettings(con_handle);

  //dev bypass
  bypassDev(con_handle);

  //getkeys
  while (1){
    if(GetAsyncKeyState(VK_TAB) & 0x01){
      WriteConsole(con_handle, "pressed TAB\n", 13, NULL, NULL);
    }
  }
  return 0;
}


BOOL WINAPI DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:{
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Main, hModule, NULL, NULL);
    break;
  }
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}
