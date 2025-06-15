#pragma once
#include <windows.h>
BOOL WINAPI OutputDebugStringAHook(LPCSTR lpOutputString);
void setOutputDebugStringAHook();
