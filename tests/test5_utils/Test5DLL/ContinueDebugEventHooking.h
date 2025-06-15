#pragma once
#include <windows.h>
BOOL WINAPI ContinueDebugEventHook(DWORD, DWORD, DWORD);
void setContinueDebugEventHook();
