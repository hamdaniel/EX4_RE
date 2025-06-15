#pragma once
#include <windows.h>
#include <winternl.h>
NTSTATUS WINAPI NtQueryInformationProcessHook(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
void setNtQueryInformationProcessHook();
