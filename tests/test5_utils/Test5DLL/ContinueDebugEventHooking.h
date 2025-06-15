#pragma once

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <fstream>
#include <iostream>
#include <ios>
#include <string>
#include <stdlib.h>

BOOL WINAPI continueDebugEventHook(DWORD, DWORD, DWORD);

void setContinueDebugEventHook();
