#include "sigscan.h"
#include "steam/steam_api.h"
#include <Psapi.h>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
#include <ostream>
#include <process.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <thread>
#include <tlhelp32.h>
#include <utility>
#include <vector>
#include <windows.h>
#include <winuser.h>
#include <cstdlib>
#include <filesystem>
#include "kiero.h"
#include <d3d9.h>
#include <Windows.h>

#define WM_KEYUP                        0x0101
#define WM_KEYDOWN                      0x0100

namespace fsex = std::experimental::filesystem;
namespace fs = std::filesystem;
using namespace std;
using std::string;

int getPID() {
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

  if (Process32First(snapshot, &entry) == TRUE) {
    while (Process32Next(snapshot, &entry) == TRUE) {
      if (stricmp(entry.szExeFile, "ScrapMechanic.exe") == 0) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
        CloseHandle(hProcess);

        return entry.th32ProcessID;
      }
    }
  }

  CloseHandle(snapshot);

  return -1;
}

HWND FindWindowByProcessIdAndClassName(DWORD pid, TCHAR* szWndClassName)
{
    HWND hCurWnd = GetTopWindow(0);
    while (hCurWnd != NULL)
    {
        DWORD cur_pid;
        DWORD dwTheardId = GetWindowThreadProcessId(hCurWnd, &cur_pid);
                
        if (cur_pid == pid)
        {
            if (IsWindowVisible(hCurWnd) != 0)
            {
                TCHAR szClassName[256];
                GetClassName(hCurWnd, szClassName, 256);
                if (_tcscmp(szClassName,szWndClassName)==0)
                    return hCurWnd;
            }
        }
        hCurWnd = GetNextWindow(hCurWnd, GW_HWNDNEXT);
    }
    return NULL;
}

std::vector<uint8_t> bypassDev(HANDLE con_handle) {
  SignatureScanner sigScanner(L"ScrapMechanic.exe");

  constexpr size_t len = 9;

  if (!sigScanner.readMemory()) {
    WriteConsole(con_handle, "failed to find dev flag\n", 21, NULL, NULL);
    std::vector<uint8_t> signature_copy;
    return signature_copy;
  }

  DWORD64 compare_flag = sigScanner.scan("\x38\x43\x78\x0f\x85\xa2\x0a\x00\x00", "xxxxx????");
  if (!compare_flag) {
    WriteConsole(con_handle, "failed to find dev flag\n", 21, NULL, NULL);
    std::vector<uint8_t> signature_copy;
    return signature_copy;
  }

  string line = "found dev flag " + std::to_string(compare_flag) + '\n';
  WriteConsole(con_handle, line.c_str(), line.size(), NULL, NULL);

  LPVOID dst = (LPVOID) compare_flag;
  DWORD oldProtection;
  DWORD temp;

  // Allow modifications of the target function
  VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProtection);

  std::vector<uint8_t> signature_copy((uint8_t *) compare_flag, (uint8_t *) compare_flag + len);

  // Replace the cmp and jne instructions with NOP
  memset((void *) compare_flag, 0x90, len);

  // Restore protection
  VirtualProtect(dst, len, oldProtection, &temp);

  return signature_copy;
}

void loadSettings(HANDLE con_handle){
  DWORD processID = getPID();

  HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );

  char filePath[MAX_PATH];
  GetModuleFileNameExA(hProcess, NULL, (LPSTR) filePath, MAX_PATH);

  WriteConsole(con_handle, filePath, strlen(filePath), NULL, NULL);

  auto sm = fs::absolute(fs::path(filePath)).parent_path().parent_path();
  sm /= "Sythe";
  fs::create_directory(sm);
  std::cout << sm << '\n';
  sm /= "keybinds";
  std::cout << sm << '\n';

  // create template forkeybinds
  

  if (fs::exists(sm)) {
    std::fstream data_file;
    data_file.open(sm, std::fstream::out);
    // return template
  }else{
    // return data
  }
}

void writeUserData(HANDLE con_handle) {
  SetConsoleTextAttribute(con_handle, FOREGROUND_RED);

  char logo[] = "  ██████▓██   ██▓▄▄▄█████▓ ██░ ██ ▓█████ \n▒██    ▒ ▒██  ██▒▓  ██▒ ▓▒▓██░ ██▒▓█ "
          "  ▀ \n░ ▓██▄    ▒██ ██░▒ ▓██░ ▒░▒██▀▀██░▒███   \n  ▒   ██▒ ░ ▐██▓░░ ▓██▓ ░ ░▓█ "
          "░██ ▒▓█  ▄ \n▒██████▒▒ ░ ██▒▓░  ▒██▒ ░ ░▓█▒░██▓░▒████▒\n▒ ▒▓▒ ▒ ░  ██▒▒▒   ▒ ░░ "
          "   ▒ ░░▒░▒░░ ▒░ ░\n░ ░▒  ░ ░▓██ ░▒░     ░     ▒ ░▒░ ░ ░ ░  ░\n░  ░  ░  ▒ ▒ ░░   "
          " ░       ░  ░░ ░   ░   \n      ░  ░ ░               ░  ░  ░   ░  ░\n         ░ "
          "░                             \nInjected into ScrapMechanic.exe\n";

  WriteConsole(con_handle, logo, strlen(logo), NULL, NULL);

  CSteamID steamID = SteamUser()->GetSteamID();
  const char *steamNAME = SteamFriends()->GetPersonaName();

  using std::string;

  string line1 = "username: " + string(steamNAME) + '\n';
  string line2 = "ID: " + std::to_string(steamID.ConvertToUint64()) + '\n';

  WriteConsole(con_handle, line1.c_str(), line1.size(), NULL, NULL);
  WriteConsole(con_handle, line2.c_str(), line2.size(), NULL, NULL);
}

DWORD WINAPI Main(HMODULE hModule) {
  DWORD processID = getPID();
  const HANDLE con_handle = GetStdHandle(STD_OUTPUT_HANDLE);

  // console logo and user data
  writeUserData(con_handle);

  // load settings
  loadSettings(con_handle);

  // dev bypass
  std::vector<uint8_t> signature = bypassDev(con_handle);
  std::fflush(stdout);
  std::cout << std::flush;

  if (signature.size() == 0) {
    std::cout << "An error occurred in bypassDev\n";
  } else {
    string line = "Signature: ";

    for (size_t i = 0; i < signature.size(); ++i) {
      line += std::to_string(signature[i]);
      line += ' ';
    }

    line += '\n';
    WriteConsole(con_handle, line.c_str(), line.size(), NULL, NULL);
  }

  TCHAR className[256];
  GetClassName(FindWindowA(NULL, "Scrap Mechanic"), className, 256);


  

  // getkeys
  while (1) {
    bool isFocused = GetForegroundWindow() == FindWindowByProcessIdAndClassName(processID, className);

    // printf("isFocused=%d\n", isFocused);
    if (isFocused) {
      std::vector<int> pressedKeys;
      constexpr int MAX_KEYS = 4;

      for (int i = VK_LBUTTON; i < VK_OEM_CLEAR && pressedKeys.size() < MAX_KEYS; i++) {
          if (GetAsyncKeyState(i) & 0x01) { // if this key is being pressed add it to the array
              pressedKeys.push_back(i);
          }
      }
      if (pressedKeys.size() > 0) {
          std::cout << "pressed ";
          for (auto key : pressedKeys) {
              std::cout << key << ' ';
          }
          std::cout << '\n' << std::flush;
      }
    }
  }
  return 0;
}

// Create the type of function that we will hook
typedef long(__stdcall* EndScene)(LPDIRECT3DDEVICE9);
static EndScene oEndScene = NULL;

// Declare the detour function
long __stdcall hkEndScene(LPDIRECT3DDEVICE9 pDevice)
{
  // ... Your magic here ...
  
  // static bool init = false;
  // if (!init)
  // {
  //  MessageBox(0, "Boom! It's works!", "Kiero", MB_OK);
  //  init = true;
  // }
  
  return oEndScene(pDevice);
}

int kieroExampleThread()
{
  if (kiero::init(kiero::RenderType::D3D9) == kiero::Status::Success)
  // or
  if (kiero::init(kiero::RenderType::Auto) == kiero::Status::Success)
  {
    // define KIERO_USE_MINHOOK must be 1
    // the index of the required function can be found in the METHODSTABLE.txt
    kiero::bind(42, (void**)&oEndScene, hkEndScene);
    
    // If you just need to get the function address you can use the kiero::getMethodsTable function
    oEndScene = (EndScene)kiero::getMethodsTable()[42];
  }

  return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
      CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)kieroExampleThread, NULL, 0, NULL);
      CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) Main, hModule, NULL, NULL);
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
