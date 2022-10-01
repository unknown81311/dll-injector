#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <Psapi.h>


class SignatureScanner {
private:
	LPCWSTR moduleName;
	DWORD64 moduleBase;
	DWORD moduleSize;
	HMODULE moduleHandle;

	MODULEINFO GetModuleInfo(LPCWSTR moduleName) {
		MODULEINFO moduleInfo = { 0 };
		this->moduleHandle = GetModuleHandleW(moduleName);
		if (this->moduleHandle == NULL)
			return moduleInfo;

		GetModuleInformation(GetCurrentProcess(), this->moduleHandle, &moduleInfo, sizeof(MODULEINFO));

		return moduleInfo;
	}

	BYTE* data;

public:
	SignatureScanner(LPCWSTR moduleName) {
		this->moduleName = moduleName;

		MODULEINFO moduleInfo = GetModuleInfo(moduleName);

		if (moduleInfo.SizeOfImage == 0) {
			return;
		}

		this->moduleBase = (DWORD64) moduleInfo.lpBaseOfDll;
		this->moduleSize = moduleInfo.SizeOfImage;
	}

	~SignatureScanner() {
		delete[] data;
	}

	bool readMemory() {
		data = new BYTE[this->moduleSize];

		if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)this->moduleBase, this->data, this->moduleSize, NULL)) {
#pragma warning(suppress : 4996)
			return false;
		}

		return true;
	}

	DWORD64 scan(const char* signature, const char* mask, DWORD64 offset) {
		size_t length = strlen(mask);

		for (DWORD64 i = 0; i < this->moduleSize - length - 1; i++) {

			bool found = true;

			for (size_t j = 0; j < length; j++) {
				found &= mask[j] == '?' || signature[j] == *(char*)(this->moduleBase + i + j);
			}

			if (found) {
				return this->moduleBase + i + offset;
			}
		}

		return NULL;
	}

	DWORD64 scan(const char* signature, const char* mask) {
		return this->scan(signature, mask, 0);
	}

};

#undef ERROR_GETMODULE