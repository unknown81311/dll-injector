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
#include "sigscanner.h"
#include <limits>

MODULEINFO GetModuleInfo(LPCWSTR moduleName) {
  HMODULE moduleHandle;
  MODULEINFO moduleInfo = { 0 };
  moduleHandle = GetModuleHandleW(moduleName);
  if (moduleHandle == NULL)
    return moduleInfo;

  GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(MODULEINFO));

  return moduleInfo;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {

  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:{
    //setup console prints
    FILE *stream;
    freopen_s(&stream, "CONOUT$", "w", stdout);

    const HANDLE con_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    //console logo and user data
    SetConsoleTextAttribute(con_handle, FOREGROUND_RED);

    char logo[] = "  ██████▓██   ██▓▄▄▄█████▓ ██░ ██ ▓█████ \n▒██    ▒ ▒██  ██▒▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ \n░ ▓██▄    ▒██ ██░▒ ▓██░ ▒░▒██▀▀██░▒███   \n  ▒   ██▒ ░ ▐██▓░░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ \n▒██████▒▒ ░ ██▒▓░  ▒██▒ ░ ░▓█▒░██▓░▒████▒\n▒ ▒▓▒ ▒ ░  ██▒▒▒   ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░\n░ ░▒  ░ ░▓██ ░▒░     ░     ▒ ░▒░ ░ ░ ░  ░\n░  ░  ░  ▒ ▒ ░░    ░       ░  ░░ ░   ░   \n      ░  ░ ░               ░  ░  ░   ░  ░\n         ░ ░                             \nInjected into ScrapMechanic.exe\n";
    
    assert(WriteConsole(con_handle, logo, strlen(logo), NULL, NULL));

    CSteamID steamID = SteamUser()->GetSteamID();
    const char * steamNAME = SteamFriends()->GetPersonaName();

    using std::string;

    string line1 = "username: " + string(steamNAME) + '\n';
    string line2 = "ID: " + std::to_string(steamID.ConvertToUint64()) + '\n';

    assert(WriteConsole(con_handle, line1.c_str(), line1.size(), NULL, NULL));
    assert(WriteConsole(con_handle, line2.c_str(), line2.size(), NULL, NULL));

    //bypass dev
    LPCSTR devSignature = "\x38\x83\xF0\x00\x00\x00\x0F\x85";
    LPCSTR devMask = "xxxxxxxx";

    SignatureScanner SigScanner;
    if (SigScanner.GetProcess("ScrapMechanic.exe"))
    {
      module mod = SigScanner.GetModule("ScrapMechanic.exe");
      // scanning for the address of the variable:
      DWORD moduleBase = SigScanner.FindSignature(mod.dwBase, mod.dwSize, devSignature, devMask) + 1;

      // Let's read the value of it:
      cout << uppercase << hex << moduleBase << endl;
      
      int devFlag = SigScanner.ReadMemory<int>(moduleBase);

      
      string line3 = "found signicture?: " + std::to_string(devFlag) + "\n";
      WriteConsole(con_handle, line3.c_str(), line3.size(), NULL, NULL);
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
