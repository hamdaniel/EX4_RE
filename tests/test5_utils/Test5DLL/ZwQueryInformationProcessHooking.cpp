#include "pch.h"
#include "ZwQueryInformationProcessHooking.h"
NTSTATUS WINAPI ZwQueryInformationProcessHook(HANDLE hProcess, PROCESSINFOCLASS pic, PVOID p, ULONG u, PULONG pu) {
    ExitProcess(5006);
    return (NTSTATUS)0; // never reached
}
void setZwQueryInformationProcessHook() {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "ZwQueryInformationProcess");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)ZwQueryInformationProcessHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
