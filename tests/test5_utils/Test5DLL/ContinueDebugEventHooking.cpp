#include "pch.h"
#include "ContinueDebugEventHooking.h"
BOOL WINAPI ContinueDebugEventHook(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus) {
    ExitProcess(5010);
    return FALSE; // never reached
}
void setContinueDebugEventHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "ContinueDebugEvent");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)ContinueDebugEventHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
