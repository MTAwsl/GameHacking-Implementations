#include "mem.h"

uintptr_t mem::FindDMAddress(uintptr_t base, std::vector<unsigned int> offsets)
{
    uintptr_t addr = base;
    for (int i = 0; i < offsets.size(); i++) {
        addr = (uintptr_t)*(DWORD*)addr;
        addr += offsets[0];
    }
    return addr;
}

uintptr_t mem::FindDMAddressEx(HANDLE hProc, uintptr_t base, std::vector<unsigned int> offsets)
{
    uintptr_t addr = base;
    for (int i = 0; i < offsets.size(); i++) {
        ReadProcessMemory(hProc, (byte*)addr, &addr, sizeof(addr), nullptr);
        addr += offsets[0];
    }
    return addr;
}

uintptr_t mem::aobscan(uintptr_t start, uintptr_t end, LPCWSTR pattern, size_t size)
{
    if (end < start) {
#ifdef _DEBUG
        MessageBoxW(NULL, L"Error in aobscan: \nThe end address is smaller than the start address.", L"ERROR", MB_OK | MB_ICONERROR);
#endif
        return NULL;
    }
    for (; start < end - size; start++) {

    }

    return uintptr_t();
}
