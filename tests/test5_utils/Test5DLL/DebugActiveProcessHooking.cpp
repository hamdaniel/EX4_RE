#include "pch.h"
#include "DebugActiveProcessHooking.h"
BOOL WINAPI DebugActiveProcessHook(DWORD dwProcessId) {
    ExitProcess(5007);
    return FALSE; // never reached
}
void setDebugActiveProcessHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "DebugActiveProcess");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)DebugActiveProcessHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
