#pragma once
#include <Windows.h>

namespace proc {
	DWORD GetProcId(LPCWSTR procName);
	uintptr_t GetModuleBaseAddress(HANDLE hProc, LPCWSTR moduleName);
	uintptr_t GetThreadStackBase(void);
	uintptr_t DLLInjectFile(HANDLE hProc, LPCWSTR dllPath);
	bool DLLInjectBuffer(byte* buf);
	bool DLLDetach(HINSTANCE hInstance);  // Communicate with the framework process and DLL
}