#pragma once
#include <Windows.h>
#include <vector>

namespace offset {
	uintptr_t FindDMAddress(uintptr_t base, std::vector<unsigned int> offsets);
	uintptr_t FindDMAddressEx(HANDLE hProc, uintptr_t base, std::vector<unsigned int> offsets);
}