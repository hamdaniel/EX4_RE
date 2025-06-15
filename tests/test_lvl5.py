import subprocess
import time
import psutil
import sys
import os
import re

def run_injector():
    exe_name = "tictactoe.exe"
    dll_name = "Test5DLL.dll"
    injector = "injector.exe"
    proc = subprocess.Popen([
        injector, exe_name, dll_name
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait(timeout=10)
    if proc.returncode != 0:
        print(f"[ERROR] Injector failed with code {proc.returncode}")
        sys.exit(1)

def run_debugged_process():
    exe_name = "tictactoe.exe"
    args = ["activate"]
    gdb_command = ["gdb", "--args", exe_name] + args
    proc = subprocess.Popen(
        gdb_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(2)
    proc.stdin.write("run\n")
    proc.stdin.flush()
    return proc

def get_child_pid(proc):
    gdb_proc = psutil.Process(proc.pid)
    for _ in range(10):
        children = gdb_proc.children(recursive=False)
        if children:
            return children[0]
        time.sleep(0.5)
    return None

def open_ports_test(pid):
    time.sleep(4)
    try:
        for _ in range(5):
            output = subprocess.check_output(["netstat", "-ano"], text=True)
            for line in output.splitlines():
                if line.strip().endswith(str(pid)):
                    return False
            time.sleep(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] netstat failed: {e}")
    return True

def normal_game_behavior_test(gdb_proc):
    moves = "1\n4\n2\n5\n3\n"
    try:
        gdb_proc.stdin.write(moves)
        gdb_proc.stdin.flush()
        time.sleep(1)
        stdout, _ = gdb_proc.communicate(timeout=2)
        win_indicators = ["Player X wins!\n"]
        for indicator in win_indicators:
            if indicator in stdout:
                return True
        return False
    except subprocess.TimeoutExpired:
        gdb_proc.kill()
        gdb_proc.wait()
        return False
    except Exception as e:
        return False

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
                print(f"FAILED: Found anti-debugging API: {api.decode()}")
                return False
    return True

def main():
    # 1. Scan for anti-debugging APIs
    print("[TEST 0] Scanning for anti-debugging APIs...")
    if not scan_for_antidebug("tictactoe.exe"):
        print("FAILED: Anti-debugging API found in binary.")
        return
    print("PASSED: No anti-debugging APIs found in binary.")

    # 2. Run injector
    print("[TEST 1] Running injector...")
    run_injector()

    # 3. Start debugged process under gdb
    gdb_proc = run_debugged_process()
    tictactoe_proc = get_child_pid(gdb_proc)
    if not tictactoe_proc:
        print("[ERROR] Could not find tictactoe process")
        return

    failed_tests = False
    print("\n[TEST 2/3]")
    if open_ports_test(tictactoe_proc.pid):
        print("PASSED: No TCP server detected.")
    else:
        print("FAILED: Debugger detected suspicious activity.")
        failed_tests = True

    if not failed_tests:
        print("\n[TEST 3/3]")
        if normal_game_behavior_test(gdb_proc):
            print("PASSED: Expected game behavior")
        else:
            print("FAILED: Game behaves unexpectedly.")
            failed_tests = True
    if not failed_tests:
        print("\nLevel 5 passed!\n")

    try:
        gdb_proc.stdin.write("quit\n")
        gdb_proc.stdin.flush()
        time.sleep(0.5)
        gdb_proc.stdin.write("y\n")
        gdb_proc.stdin.flush()
    except Exception:
        pass
    try:
        gdb_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        gdb_proc.kill()

if __name__ == "__main__":
    main()
