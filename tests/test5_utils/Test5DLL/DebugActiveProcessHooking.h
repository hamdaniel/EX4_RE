#pragma once
#include <windows.h>
BOOL WINAPI DebugActiveProcessHook(DWORD dwProcessId);
void setDebugActiveProcessHook();
