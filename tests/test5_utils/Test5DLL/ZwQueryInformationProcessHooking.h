#pragma once
#include <windows.h>
#include <winternl.h>
NTSTATUS WINAPI ZwQueryInformationProcessHook(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
void setZwQueryInformationProcessHook();
