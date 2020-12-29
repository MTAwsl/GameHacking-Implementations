#include <Windows.h>
#include <TlHelp32.h>
#include "process.h"

DWORD proc::GetProcId(LPCWSTR procName) {
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		MessageBoxW(NULL, L"CreateToolhelp32Snapshot Failed", L"Error", MB_OK | MB_ICONERROR);
#endif
		return pid;
	}
	PROCESSENTRY32 procEntry;
	ZeroMemory(&procEntry, sizeof(procEntry));
	procEntry.dwSize = sizeof(procEntry);

	// Walk through all process
	Process32First(hSnap, &procEntry);
	do {
		if (!wcscmp(procName, procEntry.szExeFile)) {
			pid = procEntry.th32ProcessID;
			return pid;
		}
	} while (Process32Next(hSnap, &procEntry));
	return pid;
}

uintptr_t proc::GetModuleBaseAddress(HANDLE hProc, LPCWSTR moduleName)
{
	uintptr_t moduleBase = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		MessageBoxW(NULL, L"CreateToolhelp32Snapshot Failed", L"Error", MB_OK | MB_ICONERROR);
#endif
		return moduleBase;
	}
	MODULEENTRY32 modEntry;
	ZeroMemory(&modEntry, sizeof(modEntry));
	modEntry.dwSize = sizeof(modEntry);

	// Walk through all process
	Module32First(hSnap, &modEntry);
	do {
		if (!wcscmp(moduleName, modEntry.szModule)) {
			moduleBase = (uintptr_t)modEntry.modBaseAddr;
			return moduleBase;
		}
	} while (Module32Next(hSnap, &modEntry));
	return moduleBase;
}

uintptr_t proc::DLLInjectFile(HANDLE hProc, LPCWSTR dllPath) {
	size_t size = sizeof(WCHAR) * (wcslen(dllPath) + 1);
	void* buf = VirtualAllocEx(hProc, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buf == NULL) {
#ifdef _DEBUG
		MessageBoxW(NULL, L"VirtualAllocEx Failed.", L"Error", MB_OK | MB_ICONERROR);
#endif
		return NULL;
	}
	bool retn = WriteProcessMemory(hProc, buf, dllPath, size, nullptr);
	if (retn == NULL) {
#ifdef _DEBUG
		MessageBoxW(NULL, L"WriteProcessMemory Failed.", L"Error", MB_OK | MB_ICONERROR);
#endif
		return NULL;
	}
	HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW, buf, 0, nullptr);
	if (hThread == NULL) {
#ifdef _DEBUG
		MessageBoxW(NULL, L"CreateRemoteThread Failed.", L"Error", MB_OK | MB_ICONERROR);
#endif
		return NULL;
	}
	CloseHandle(hThread);
	return (uintptr_t)buf;
} 

// VirtualFree