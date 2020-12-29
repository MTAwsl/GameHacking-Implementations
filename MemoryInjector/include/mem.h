#pragma once
#include <Windows.h>
#include <vector>

namespace mem {
	uintptr_t FindDMAddress(uintptr_t base, std::vector<unsigned int> offsets);
	uintptr_t FindDMAddressEx(HANDLE hProc, uintptr_t base, std::vector<unsigned int> offsets);
	uintptr_t aobscan(uintptr_t start, uintptr_t end, LPCWSTR conditionCode, size_t size);
	uintptr_t aobscanEx(HANDLE hProc, uintptr_t start, uintptr_t end, LPCWSTR conditionCode);
}