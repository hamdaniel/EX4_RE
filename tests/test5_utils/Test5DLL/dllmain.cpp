#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <fstream>
#include <iostream>
#include <ios>
#include <string>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>

#include "isDebuggerPresentHooking.h"
#include "CheckRemoteDebuggerPresentHooking.h"
#include "OutputDebugStringAHooking.h"
#include "OutputDebugStringWHooking.h"
#include "NtQueryInformationProcessHooking.h"
#include "ZwQueryInformationProcessHooking.h"
#include "DebugActiveProcessHooking.h"
#include "DebugBreakHooking.h"
#include "DebugSetProcessKillOnExitHooking.h"
#include "ContinueDebugEventHooking.h"

void set_being_debugged_flag()
{
    // PEB is pointed to by the FS:[0x30] segment register on 32-bit Windows
    BYTE* pBeingDebugged = (BYTE*)__readfsbyte(0x30 + 2);

    // This is incorrect, need to get pointer first:

    // Get the PEB base address from FS:[0x30]
    PBYTE pPEB = (PBYTE)__readfsdword(0x30);

    // BeingDebugged is at offset 0x2 inside the PEB
    pPEB[2] = 1;  // Set BeingDebugged to 1
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        set_being_debugged_flag(); // make process think it is debugged
        setIsDebuggerPresentHook();
        setCheckRemoteDebuggerPresentHook();
        setOutputDebugStringAHook();
        setOutputDebugStringWHook();
        setNtQueryInformationProcessHook();
        setZwQueryInformationProcessHook();
        setDebugActiveProcessHook();
        setDebugBreakHook();
        setDebugSetProcessKillOnExitHook();
        setContinueDebugEventHook();
    }
    return TRUE;
}
