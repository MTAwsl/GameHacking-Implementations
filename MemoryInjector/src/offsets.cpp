#include "offsets.h"

uintptr_t offset::FindDMAddress(uintptr_t base, std::vector<unsigned int> offsets)
{
    uintptr_t addr = base;
    for (int i = 0; i < offsets.size(); i++) {
        addr = (uintptr_t)*(DWORD*)addr;
        addr += offsets[0];
    }
    return addr;
}

uintptr_t offset::FindDMAddressEx(HANDLE hProc, uintptr_t base, std::vector<unsigned int> offsets)
{
    uintptr_t addr = base;
    for (int i = 0; i < offsets.size(); i++) {
        ReadProcessMemory(hProc, (byte*)addr, &addr, sizeof(addr), nullptr);
        addr += offsets[0];
    }
    return addr;
}
