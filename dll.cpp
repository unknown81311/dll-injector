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

INT isSteamLoaded()
{
    DWORD processID = getPID();

    if(processID == -1){
      return -1;
    }

    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Get a handle to the process.

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, processID );
    if (NULL == hProcess)
        return 1;

   // Get a list of all the modules in this process.

    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
                                      sizeof(szModName) / sizeof(TCHAR))){

                // Print the module name and handle value.
                if (szModName == "F:\\SteamLibrary\\steamapps\\common\\Scrap Mechanic\\Release\\steam_api64.dll"){
                  _tprintf(TEXT("found steam: %s (0x%08X)\n"), szModName, hMods[i]);
                }
            }
        }
    }
    
    // Release the handle to the process.

    CloseHandle( hProcess );

    return 0;
}

bool OverwriteOps() {
  const HANDLE con_handle = GetStdHandle(STD_OUTPUT_HANDLE);

	SignatureScanner sigScanner(L"ScrapMechanic.exe");
	if (!sigScanner.readMemory()) {
		string line = "Failed while reading memory\n";
		assert(WriteConsole(con_handle, line.c_str(), line.size(), NULL, NULL));
		std::cout << line;
		return false;
	}

	DWORD64 compare_flag = sigScanner.scan("\x38\x43\x78\x0f\x85\xa2\x0a\x00\x00", "xxxxx????");
	if (!compare_flag) {
		string line = "Failed while scanning\n";
		assert(WriteConsole(con_handle, line.c_str(), line.size(), NULL, NULL));
		std::cout << line;
		return false;
	}

  string line3 = "compare_flag " + std::to_string(compare_flag) + "\n";
  assert(WriteConsole(con_handle, line3.c_str(), line3.length(), NULL, NULL));

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

	return true;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:{

    const HANDLE con_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    //console logo and user data
    SetConsoleTextAttribute(con_handle, FOREGROUND_RED);

    char logo[] = "  ██████▓██   ██▓▄▄▄█████▓ ██░ ██ ▓█████ \n▒██    ▒ ▒██  ██▒▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ \n░ ▓██▄    ▒██ ██░▒ ▓██░ ▒░▒██▀▀██░▒███   \n  ▒   ██▒ ░ ▐██▓░░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ \n▒██████▒▒ ░ ██▒▓░  ▒██▒ ░ ░▓█▒░██▓░▒████▒\n▒ ▒▓▒ ▒ ░  ██▒▒▒   ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░\n░ ░▒  ░ ░▓██ ░▒░     ░     ▒ ░▒░ ░ ░ ░  ░\n░  ░  ░  ▒ ▒ ░░    ░       ░  ░░ ░   ░   \n      ░  ░ ░               ░  ░  ░   ░  ░\n         ░ ░                             \nInjected into ScrapMechanic.exe\n";
    
    assert(WriteConsole(con_handle, logo, strlen(logo), NULL, NULL));


    //get steam dll
    int iststeamloaded = isSteamLoaded();
    assert(iststeamloaded);


    CSteamID steamID = SteamUser()->GetSteamID();
    const char * steamNAME = SteamFriends()->GetPersonaName();

    using std::string;

    string line1 = "username: " + string(steamNAME) + '\n';
    string line2 = "ID: " + std::to_string(steamID.ConvertToUint64()) + '\n';

    assert(WriteConsole(con_handle, line1.c_str(), line1.size(), NULL, NULL));
    assert(WriteConsole(con_handle, line2.c_str(), line2.size(), NULL, NULL));


    //dev bypass
    bool overwritten = OverwriteOps();
    assert(overwritten);
    if(overwritten){
      string line3 = "steam is loaded or smth\n";
      assert(WriteConsole(con_handle, line2.c_str(), line2.size(), NULL, NULL));
    }
    
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
