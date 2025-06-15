#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Shlwapi.h>

LPSTR DLL_PATH;

BOOL dllInjector(const char* dllpath, DWORD pID);

// Pipe handles (global for simplicity)
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;

int main(int argc, char** argv)
{
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE g_hChildStd_IN_Rd = NULL;
    HANDLE g_hChildStd_OUT_Wr = NULL;

    // Create pipe for child STDOUT
    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
        printf("Stdout pipe creation failed\n");
        return 1;
    }
    SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);

    // Create pipe for child STDIN
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
        printf("Stdin pipe creation failed\n");
        return 1;
    }
    SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);

    // Set up STARTUPINFO with redirected handles
    STARTUPINFOA siStartInfo;
    PROCESS_INFORMATION pi;
    ZeroMemory(&siStartInfo, sizeof(siStartInfo));
    siStartInfo.cb = sizeof(siStartInfo);
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    ZeroMemory(&pi, sizeof(pi));

    // Create child process
    DLL_PATH = (LPSTR)"Test5DLL.dll";
    LPSTR exePath = (LPSTR)"tictactoe.exe";
    LPSTR cmdLine = (LPSTR)"tictactoe.exe activate";

    DWORD creationFlags = CREATE_SUSPENDED;

    if (!CreateProcessA(exePath, cmdLine, NULL, NULL, TRUE, creationFlags, NULL, NULL, &siStartInfo, &pi)) {
        printf("Couldn't open process %s\n", exePath);
        return 1;
    }
    printf("Process created successfully with PID: %lu\n", pi.dwProcessId);
    
    // Close unneeded handles in parent
    CloseHandle(g_hChildStd_IN_Rd);
    CloseHandle(g_hChildStd_OUT_Wr);

    // Inject DLL
    if (!dllInjector(DLL_PATH, pi.dwProcessId)) {
        printf("Couldn't inject DLL\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    Sleep(1000); // Wait for DLL to load
    ResumeThread(pi.hThread);
    printf("Injected DLL successfully\n");

    // Write simulated input to child stdin
    const char* input = "1\n2\n3\n4\n5\n6\n7\n";
    DWORD bytesWritten;
    WriteFile(g_hChildStd_IN_Wr, input, (DWORD)strlen(input), &bytesWritten, NULL);
    CloseHandle(g_hChildStd_IN_Wr); // Signal EOF

    // Read child stdout and write to file
    FILE* logFile = fopen("output.log", "w");
    if (!logFile) {
        printf("Failed to open output.log for writing\n");
        return 1;
    }

    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(g_hChildStd_OUT_Rd, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        fputs(buffer, logFile);
        fflush(logFile);
    }

    fclose(logFile);
    CloseHandle(g_hChildStd_OUT_Rd);

    // Wait for child process to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        printf("Injected process exited with code: %lu\n", exitCode);
    } else {
        printf("Failed to get exit code.\n");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    system("del /F output.log >nul 2>&1");
    return 0;
}

BOOL dllInjector(const char* dllpath, DWORD pID)
{
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!pHandle) {
        printf("couldn't open process with perms\n");
        return FALSE;
    }

    LPVOID remoteLoadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    LPVOID remoteString = VirtualAllocEx(pHandle, NULL, strlen(DLL_PATH) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pHandle, remoteString, dllpath, strlen(dllpath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteLoadLib, remoteString, 0, NULL);
    if (hThread == NULL) {
        CloseHandle(pHandle);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(pHandle);
    return TRUE;
}