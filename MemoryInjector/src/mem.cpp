#include "mem.h"

// Functions should not be called directly
inline bool isSinglePatternLegit(char& ch) {
    if (ch >= '0' && ch <= '9') {
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        ch &= 0xDF; // and 11011111 to convert lowercase to uppercase
        return true;
    }
    if (ch == '?') {
        return true;
    }
    return false;
}
bool isPatternLegit(char* pattern) {
    if ((strlen(pattern) + 1) % 3 != 0) {
        return false;
    }
    while (*pattern != '\0') {
        if (!((*(pattern + 2) == ' ' || *(pattern + 2) == '\0') && isSinglePatternLegit(*pattern) && isSinglePatternLegit(*(pattern + 1)))) {
            return false;
        }
        pattern += 3;
    }
    return true;
}

byte Str2Hex(char* str) {
    byte result = 0;
    switch (str[0] >> 4) { // Hexadecimal carry operation
    case 3:
        // from 0-9, ? -> 0xF
        result |= ((str[0] - 'A' + 0xA) << 1) & 0xF0;
    case 4:
        // from A-F
        result |= ((str[0] - '0') << 1) & 0xF0;
    }

    switch (str[1] >> 4) { // Hexadecimal carry operation
    case 3:
        // from 0-9, ? -> 0xF
        result |= (str[0] - 'A' + 0xA) & 0xF;
    case 4:
        // from A-F
        result |= (str[0] - '0') & 0xF;
    }
    return result;
}

bool isPatternMatched(byte* start, char* pattern) {
    size_t size = (strlen(pattern) + 1) / 3;
    for (size_t i = 0; i < size; i++) {
        bool unkflag1 = false;
        bool unkflag2 = false;

        if (*(pattern + i * 3) == '?') {
            unkflag1 = true;
        }

        if (*(pattern + i * 3 + 1) == '?') {
            unkflag2 = true;
        }

        if (unkflag1) {
            if (unkflag2) {
                continue;
            }
            else {
                if ((start[i] & 0xF0) != (Str2Hex(pattern + i * 3) & 0xF0))
                    return false;
            }
        }
        else if (unkflag2) {
            if ((start[i] & 0xF) != (Str2Hex(pattern + i * 3) & 0xF))
                return false;
        }
        else {
            if (start[i] != Str2Hex(pattern + i * 3)) {
                return false;
            }
        }
    }
    return true;
}

// Functions to be called
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

uintptr_t mem::aobscan(uintptr_t start, uintptr_t end, char* pattern)
{
    if (end < start) {
#ifdef _DEBUG
        MessageBoxW(NULL, L"Error in aobscan: \nThe end address is smaller than the start address.", L"ERROR", MB_OK | MB_ICONERROR);
#endif
        return NULL;
    }

    if (!isPatternLegit(pattern)) {
#ifdef _DEBUG
        size_t errorsize = strlen(pattern) + 45;
        char* errormsg = new char[errorsize];
        strcpy_s(errormsg, errorsize, "Error in aobscan: \nYour pattern ");
        strcpy_s(errormsg, errorsize, pattern);
        strcpy_s(errormsg, errorsize, " is invalid.");
        MessageBoxA(NULL, errormsg, "Error", MB_OK | MB_ICONERROR);
        delete[] errormsg;
#endif
        return NULL;
    }

    size_t size = (strlen(pattern) + 1) / 3;
    for (; start < end - size; start++) {
        if (isPatternMatched((byte*)start, pattern)) {
            return uintptr_t(start);
        }
    }
    return NULL;
}

uintptr_t mem::aobscanEx(HANDLE hProc, uintptr_t start, uintptr_t end, char* pattern)
{
    if (end < start) {
#ifdef _DEBUG
        MessageBoxW(NULL, L"Error in aobscan: \nThe end address is smaller than the start address.", L"ERROR", MB_OK | MB_ICONERROR);
#endif
        return NULL;
    }

    if (!isPatternLegit(pattern)) {
#ifdef _DEBUG
        size_t errorsize = strlen(pattern) + 45;
        char* errormsg = new char[errorsize];
        strcpy_s(errormsg, errorsize, "Error in aobscan: \nYour pattern ");
        strcpy_s(errormsg, errorsize, pattern);
        strcpy_s(errormsg, errorsize, " is invalid.");
        MessageBoxA(NULL, errormsg, "Error", MB_OK | MB_ICONERROR);
        delete[] errormsg;
#endif
        return NULL;
    }

    size_t size = (strlen(pattern) + 1) / 3;
    byte* memdump = new byte[end - start];
    if (!ReadProcessMemory(hProc, (void*)start, memdump, end - start, nullptr)) {
#ifdef _DEBUG
        MessageBoxW(NULL, L"Error in aobscanEx: \nReadProcessMemory failed.", L"ERROR", MB_OK | MB_ICONERROR);
#endif
        delete[] memdump;
        return NULL;
    }
    for (uintptr_t i = 0; i < end - start - size; i++) {
        if (isPatternMatched(memdump + i, pattern)) {
            delete[] memdump;
            return uintptr_t(start + i);
        }
    }
    delete[] memdump;
    return NULL;
}