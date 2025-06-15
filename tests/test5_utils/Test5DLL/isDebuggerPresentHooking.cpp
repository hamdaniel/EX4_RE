#include "pch.h"
#include "isDebuggerPresentHooking.h"

BOOL WINAPI IsDebuggerPresentHook() {
    ExitProcess(5001);
    return FALSE; // never reached
}

void setIsDebuggerPresentHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) {
        return;
    }

    LPVOID func = GetProcAddress(h, "IsDebuggerPresent");
    if (!func) {
        return;
    }

    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)IsDebuggerPresentHook - ((BYTE*)func + 5));

    patch[0] = 0xE9; // JMP opcode
    memcpy(&patch[1], &rel, 4);

    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}