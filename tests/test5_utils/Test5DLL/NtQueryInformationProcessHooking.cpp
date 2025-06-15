#include "pch.h"
#include "NtQueryInformationProcessHooking.h"
NTSTATUS WINAPI NtQueryInformationProcessHook(HANDLE hProcess, PROCESSINFOCLASS pic, PVOID p, ULONG u, PULONG pu) {
    ExitProcess(5005);
    return (NTSTATUS)0; // never reached
}
void setNtQueryInformationProcessHook() {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    LPVOID func = GetProcAddress(h, "NtQueryInformationProcess");
    if (!func) return;
    DWORD oldProtect;
    BYTE patch[5];
    DWORD rel = (DWORD)((BYTE*)NtQueryInformationProcessHook - ((BYTE*)func + 5));
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel, 4);
    VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(func, patch, 5);
    VirtualProtect(func, 5, oldProtect, &oldProtect);
}
