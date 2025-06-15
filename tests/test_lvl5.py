import subprocess
import time
import psutil
import sys
import os
import re

def run_injector():
    injector = "tests/test5_utils/injector.exe"
    proc = subprocess.Popen([
        injector
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        proc.wait(timeout=11)
    except subprocess.TimeoutExpired:
        print("[ERROR] Injector timed out")
        proc.kill()
        proc.wait()
        try:
            stdout, stderr = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            print("[ERROR] Still couldn't read output after killing process")
        sys.exit(1)


    os.system("del /F output.log >nul 2>&1")

    if proc.returncode == 1:
        print(f"[ERROR] Couldn't create injecting thread.")
        sys.exit(1)
    elif proc.returncode == 0xFFFFFFFF:
        print(f"[ERROR] Couldn't load library.")
        sys.exit(1)
    return proc.returncode == 0

def scan_for_antidebug(filename):
    # List of suspicious API names
    suspicious = [
        b'IsDebuggerPresent',
        b'CheckRemoteDebuggerPresent',
        b'OutputDebugStringA',
        b'OutputDebugStringW',
        b'NtQueryInformationProcess',
        b'ZwQueryInformationProcess',
        b'DebugActiveProcess',
        b'DebugBreak',
        b'DebugSetProcessKillOnExit',
        b'ContinueDebugEvent',
    ]
    with open(filename, 'rb') as f:
        data = f.read()
        for api in suspicious:
            if api in data:
                return False
    return True

def main():
    # 1. Scan for anti-debugging APIs
    print("\n[TEST 1/2]")
    if not scan_for_antidebug("tictactoe.exe"):
        print("FAILED: Anti-debugging API found in binary.")
        sys.exit(1)
    print("PASSED: No anti-debugging APIs found in binary.")

    # 2. Run injector
    print("\n[TEST 2/2]")
    if not run_injector():
        print("FAILED: Suspicious anti-debugging APIs detected at runtime.")
        sys.exit(1)
    print("PASSED: No anti-debugging APIs detected at runtime.")

    print("\nLevel 5 passed!\n")


if __name__ == "__main__":
    main()
