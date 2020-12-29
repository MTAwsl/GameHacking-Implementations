#pragma once
#include <Windows.h>

namespace hook {
	void Patch(byte* dst, byte* src, size_t size);
	void Nop(byte* dst, size_t size);
	void PatchEx(HANDLE hProc, byte* dst, byte* src, size_t size);
	void NopEx(HANDLE hProc, byte* dst, size_t size);
	void Detour(void* dest, void* func, const size_t size);
	uintptr_t TrampHook(void* src, void* dst, const size_t size);
	void hook::DetourEx(HANDLE hProc, void* dst, void* func, const size_t size);
	uintptr_t TrampHookEx(HANDLE hProc, void* src, void* dst, const size_t size);
}