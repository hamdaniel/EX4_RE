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


DWORD WINAPI DisableBufferingThread(LPVOID lpParam) {
    FILE* f = NULL;
    if (fopen_s(&f, "debug_dll_log.txt", "w") == 0 && f != NULL) {
        fprintf(f, "DLL thread started\n");
        fflush(f);
        fclose(f);
    }
    else {
        // Handle fopen_s failure if needed
    }

    Sleep(1000); // wait for stdout to initialize
    setvbuf(stdout, NULL, _IONBF, 0);

    fprintf(stdout, "[DLL] stdout write from thread\n");
    fflush(stdout);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // CreateThread(NULL, 0, DisableBufferingThread, NULL, 0, NULL);
        setIsDebuggerPresentHook();
    }
    return TRUE;
}
