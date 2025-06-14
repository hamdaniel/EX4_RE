# Level 1 Automated Test Suite for tictactoe.exe
# ------------------------------------------------
# This script tests the following for future developers:
# 1. The game does NOT start a TCP server unless special activation arguments are given.
# 2. The game logic works: X can win, and a draw is detected.
# 3. When activated with a secret argument, a TCP backdoor opens and responds to a test command.
# All tests are automated and will terminate the process after each check.
# Update EXE_NAME or test logic if the game output or protocol changes.

import subprocess
import socket
import time
import os
import signal

EXE_NAME = "tictactoe.exe"
ACTIVATION_ARGS = ["activate"]
PORT = 6496
HOST = "127.0.0.1"
TEST_COMMAND = b"I AM RE SPY\n"
TIMEOUT = 5  # seconds

def run_exe_with_args(args):
    print(f"[DEBUG] Running {EXE_NAME} with args: {args}")
    return subprocess.Popen([EXE_NAME] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_port_open(host, port):
    print(f"[DEBUG] Checking if port {port} on {host} is open...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            print(f"[DEBUG] Port {port} is OPEN.")
            return True
        except (ConnectionRefusedError, socket.timeout):
            print(f"[DEBUG] Port {port} is CLOSED.")
            return False

def wait_for_server(timeout=TIMEOUT):
    print(f"[DEBUG] Waiting for server to open port {PORT} (timeout={timeout}s)...")
    for i in range(timeout * 10):
        if is_port_open(HOST, PORT):
            print(f"[DEBUG] Server detected on port {PORT} after {i*0.1:.1f}s.")
            return True
        time.sleep(0.1)
    print(f"[DEBUG] Server NOT detected on port {PORT} after {timeout}s.")
    return False

def test_tcp_command():
    print("[DEBUG] Testing TCP command...")
    try:
        with socket.create_connection((HOST, PORT), timeout=2) as sock:
            print(f"[DEBUG] Connected to {HOST}:{PORT}, sending test command...")
            sock.sendall(TEST_COMMAND)
            response = sock.recv(4096)
            print(f"[DEBUG] Received response: {response!r}")
            if b"hello re spy" in response.lower():
                print("level 1 passed: TCP command executed successfully!")
                print("Response:", response.decode(errors="ignore"))
                return True
            else:
                print("[DEBUG] Unexpected response to test command.")
                return False
    except Exception as e:
        print(f"[DEBUG] Exception in test_tcp_command: {e}")
        return False

def test_tcp_not_command():
    print("[DEBUG] Testing TCP not-command...")
    try:
        with socket.create_connection((HOST, PORT), timeout=2) as sock:
            print(f"[DEBUG] Connected to {HOST}:{PORT}, sending EXE_NAME...")
            sock.sendall(EXE_NAME.encode() + b"\n")
            response = sock.recv(4096)
            print(f"[DEBUG] Received response: {response!r}")
            if EXE_NAME.encode() in response.lower():
                print("Response:", response.decode(errors="ignore"))
                return True
            else:
                print("[DEBUG] Unexpected response to EXE_NAME command.")
                return False
    except Exception as e:
        print(f"[DEBUG] Exception in test_tcp_not_command: {e}")
        return False

def test_backdoor_activation():
    print("[DEBUG] Testing backdoor activation...")
    proc = run_exe_with_args(ACTIVATION_ARGS)
    time.sleep(1)
    if wait_for_server():
        res = test_tcp_command() and test_tcp_not_command()
    else:
        print("[DEBUG] Server did not start after activation args.")
        res = False
    proc.terminate()
    proc.wait()
    print(f"[DEBUG] Backdoor activation test result: {res}")
    return res

def test_normal_behavior():
    print("[DEBUG] Testing normal behavior (no TCP server should be open)...")
    proc = run_exe_with_args([])  # run with no args
    time.sleep(1)

    port_open = is_port_open(HOST, PORT)
    if port_open:
        print("[DEBUG] TCP server is active without activation args!")
        proc.terminate()
        proc.wait()
        return False
    proc.terminate()
    proc.wait()
    print("[DEBUG] Normal behavior test passed (no TCP server).")
    return True

def test_normal_game_x_wins():
    print("[DEBUG] Testing normal game: X wins scenario...")
    proc = subprocess.Popen([EXE_NAME], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    moves = ["1\n", "4\n", "2\n", "5\n", "3\n"]  # X wins on top row
    output = ""
    for move in moves:
        print(f"[DEBUG] Sending move: {move.strip()}")
        proc.stdin.write(move)
        proc.stdin.flush()
        time.sleep(0.1)
        chunk = proc.stdout.read(200)
        print(f"[DEBUG] Output chunk: {chunk!r}")
        output += chunk
        if "wins" in output:
            break
    proc.terminate()
    proc.wait()
    print(f"[DEBUG] Final output: {output!r}")
    if "Player X wins" in output:
        print("[DEBUG] X wins test PASSED.")
        return True
    else:
        print("[DEBUG] X wins test FAILED.")
        return False

def test_normal_game_draw():
    print("[DEBUG] Testing normal game: draw scenario...")
    proc = subprocess.Popen([EXE_NAME], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    moves = ["1\n", "2\n", "3\n", "5\n", "4\n", "6\n", "8\n", "7\n", "9\n"]  # Draw
    output = ""
    for move in moves:
        print(f"[DEBUG] Sending move: {move.strip()}")
        proc.stdin.write(move)
        proc.stdin.flush()
        time.sleep(0.1)
        chunk = proc.stdout.read(200)
        print(f"[DEBUG] Output chunk: {chunk!r}")
        output += chunk
        if "draw" in output.lower():
            break
    proc.terminate()
    proc.wait()
    print(f"[DEBUG] Final output: {output!r}")
    if "draw" in output.lower():
        print("[DEBUG] Draw test PASSED.")
        return True
    else:
        print("[DEBUG] Draw test FAILED.")
        return False

if __name__ == "__main__":
    print("[DEBUG] Starting Level 1 Automated Test Suite...")
    if not test_normal_behavior():
        print("level 1 failed: TCP server is active without the proper args!")
        exit(1)
    if not test_normal_game_x_wins() or not test_normal_game_draw():
        print("level 1 failed: normal game test failed!")
        exit(1)
    if not test_backdoor_activation():
        print("level 1 failed: backdoor activation test failed!")
        exit(1)
    print("[DEBUG] All Level 1 tests PASSED.")
