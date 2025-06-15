#include "pch.h"
#include "OutputDebugStringAHooking.h"
BOOL WINAPI OutputDebugStringAHook(LPCSTR lpOutputString) {
    ExitProcess(5003);
    return FALSE; // never reached
}
void setOutputDebugStringAHook() {
    HMODULE h = GetModuleHandleA("kernel32.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "OutputDebugStringA");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)OutputDebugStringAHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
