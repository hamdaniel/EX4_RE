#pragma once
#include <windows.h>
BOOL WINAPI OutputDebugStringWHook(LPCWSTR lpOutputString);
void setOutputDebugStringWHook();
