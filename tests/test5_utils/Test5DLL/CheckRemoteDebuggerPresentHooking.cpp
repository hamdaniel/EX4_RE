#include "pch.h"
#include "CheckRemoteDebuggerPresentHooking.h"


BOOL WINAPI checkRemoteDebuggerPresentHook(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    ExitProcess(5002);
    return FALSE; // never reached
}


void setCheckRemoteDebuggerPresentHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) {
        return;
    }

    LPVOID func = GetProcAddress(h, "CheckRemoteDebuggerPresent");
    if (!func) {
        return;
    }

    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)checkRemoteDebuggerPresentHook - ((BYTE*)func + 5));

    patch[0] = 0xE9; // JMP opcode
    memcpy(&patch[1], &rel, 4);

    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}

