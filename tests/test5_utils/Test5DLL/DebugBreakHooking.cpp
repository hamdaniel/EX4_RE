#include "pch.h"
#include "DebugBreakHooking.h"
void WINAPI DebugBreakHook() {
    ExitProcess(5008);
}
void setDebugBreakHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "DebugBreak");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)DebugBreakHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
