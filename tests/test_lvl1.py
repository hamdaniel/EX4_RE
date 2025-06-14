#!/usr/bin/env python3
"""
Level 1 Automated Test Suite for tictactoe.exe
------------------------------------------------
This script tests the following for future developers:
1. The game does NOT start a TCP server unless special activation arguments are given.
2. The game logic works: X can win, and a draw is detected.
3. When activated with a secret argument, a TCP backdoor opens and responds to a test command.

All tests are automated and will terminate the process after each check.
Update EXE_NAME or test logic if the game output or protocol changes.
"""

import subprocess
import socket
import time
import os
import sys

# Configuration
EXE_NAME = "tictactoe.exe"
ACTIVATION_ARGS = ["activate"]
PORT = 12345  # Reverted to original port from test expectations
HOST = "127.0.0.1"
TEST_COMMAND = b"I AM RE SPY"  # Restored newline for proper protocol
TIMEOUT = 5  # seconds
GAME_TIMEOUT = 10  # seconds for game interactions


def run_exe_with_args(args):
    """Start the executable with given arguments."""
    #print(f"[DEBUG] Running {EXE_NAME} with args: {args}")
    return subprocess.Popen([EXE_NAME] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def is_port_open(host, port):
    """Check if a TCP port is open and accepting connections."""
    #print(f"[DEBUG] Checking if port {port} on {host} is open...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            #print(f"[DEBUG] Port {port} is OPEN.")
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        #print(f"[DEBUG] Port {port} is CLOSED.")
        return False


def wait_for_server(timeout=TIMEOUT):
    """Wait for the TCP server to become available."""
    #print(f"[DEBUG] Waiting for server to open port {PORT} (timeout={timeout}s)...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if is_port_open(HOST, PORT):
            elapsed = time.time() - start_time
            #print(f"[DEBUG] Server detected on port {PORT} after {elapsed:.1f}s.")
            return True
        time.sleep(0.1)
    
    #print(f"[DEBUG] Server NOT detected on port {PORT} after {timeout}s.")
    return False


def test_tcp_command():
    """Test sending the special command to the TCP backdoor."""
    #print("[DEBUG] Testing TCP command...")
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as sock:
            #print(f"[DEBUG] Connected to {HOST}:{PORT}, sending test command...")
            sock.sendall(TEST_COMMAND)
            response = sock.recv(4096)
            #print(f"[DEBUG] Received response: {response!r}")
            
            if b"hello re spy" in response.lower():
                print("✓ TCP command executed successfully!")
                print("Response:", response.decode(errors="ignore"))
                return True
            else:
                #print("[DEBUG] Unexpected response to test command.")
                return False
                
    except Exception as e:
        #print(f"[DEBUG] Exception in test_tcp_command: {e}")
        return False


def test_tcp_echo():
    """Test that the TCP server echoes the executable name."""
    #print("[DEBUG] Testing TCP echo functionality...")
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as sock:
            #print(f"[DEBUG] Connected to {HOST}:{PORT}, sending EXE_NAME...")
            sock.sendall(EXE_NAME.encode() + b"\n")
            response = sock.recv(4096)
            #print(f"[DEBUG] Received response: {response!r}")
            
            if EXE_NAME.encode() in response.lower():
                print("✓ TCP echo test passed!")
                print("Response:", response.decode(errors="ignore"))
                return True
            else:
                #print("[DEBUG] Unexpected response to EXE_NAME command.")
                return False
                
    except Exception as e:
        #print(f"[DEBUG] Exception in test_tcp_echo: {e}")
        return False


def test_backdoor_activation():
    proc = run_exe_with_args(ACTIVATION_ARGS)
    time.sleep(2)
    
    # Skip is_port_open(), connect directly
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as sock:
            # Test echo
            sock.sendall(b"test")
            response1 = sock.recv(4096)
            
            # Test special command
            sock.sendall(b"I AM RE SPY")
            response2 = sock.recv(4096)
            
            return b"HELLO RE SPY" in response2
    except Exception as e:
        return False


def test_normal_behavior():
    """Test that no TCP server starts without activation arguments."""
    #print("[DEBUG] Testing normal behavior (no TCP server should be open)...")
    proc = None
    
    try:
        proc = run_exe_with_args([])  # run with no args
        time.sleep(1)  # Give process time to potentially start a server

        port_open = is_port_open(HOST, PORT)
        if port_open:
            #print("[DEBUG] ✗ TCP server is active without activation args!")
            return False
        else:
            #print("[DEBUG] ✓ Normal behavior test passed (no TCP server).")
            return True
            
    except Exception as e:
        #print(f"[DEBUG] Exception in test_normal_behavior: {e}")
        return False
        
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_normal_game_x_wins():
    """Test that X can win the game with the correct sequence of moves."""
    #print("[DEBUG] Testing normal game: X wins scenario...")
    
    # X wins on top row: positions 1, 2, 3
    # O plays positions 4, 5 to block but X gets the win
    moves = "1\n4\n2\n5\n3\n"
    
    try:
        proc = subprocess.Popen(
            [EXE_NAME], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        #print(f"[DEBUG] Sending moves: {repr(moves)}")
        stdout, stderr = proc.communicate(input=moves, timeout=GAME_TIMEOUT)
        
        #print(f"[DEBUG] Complete stdout: {stdout!r}")
        # if stderr:
            #print(f"[DEBUG] stderr: {stderr!r}")
        
        # Check for various possible win messages
        win_indicators = ["Player X wins!\n"]
        
        for indicator in win_indicators:
            if indicator in stdout:
                #print(f"[DEBUG] ✓ X wins test PASSED. Found: '{indicator}'")
                return True
        
        #print("[DEBUG] ✗ X wins test FAILED. No win message found.")
        return False
        
    except subprocess.TimeoutExpired:
        #print("[DEBUG] ✗ Game process timed out during X wins test")
        proc.kill()
        proc.wait()
        return False
        
    except Exception as e:
        #print(f"[DEBUG] Exception in test_normal_game_x_wins: {e}")
        return False


def test_normal_game_draw():
    """Test that the game correctly detects a draw scenario."""
    #print("[DEBUG] Testing normal game: draw scenario...")
    
    # Draw scenario that avoids all winning conditions:
    # Final board will look like:
    # X | O | X
    # O | O | X  
    # X | X | O
    # Positions: 1=X, 2=O, 3=X, 4=O, 5=O, 6=X, 7=X, 8=X, 9=O
    # Move sequence: X(1), O(2), X(3), O(4), X(6), O(5), X(7), O(9), X(8)
    moves = "1\n2\n3\n4\n6\n5\n7\n9\n8\n"
    
    try:
        proc = subprocess.Popen(
            [EXE_NAME], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        #print(f"[DEBUG] Sending moves: {repr(moves)}")
        stdout, stderr = proc.communicate(input=moves, timeout=GAME_TIMEOUT)
        
        #print(f"[DEBUG] Complete stdout: {stdout!r}")
        # if stderr:
            #print(f"[DEBUG] stderr: {stderr!r}")
        
        # Check for various possible draw messages
        draw_indicators = ["It's a draw!\n"]
        
        for indicator in draw_indicators:
            if indicator.lower() in stdout.lower():
                #print(f"[DEBUG] ✓ Draw test PASSED. Found: '{indicator}'")
                return True
        
        #print("[DEBUG] ✗ Draw test FAILED. No draw message found.")
        return False
        
    except subprocess.TimeoutExpired:
        #print("[DEBUG] ✗ Game process timed out during draw test")
        proc.kill()
        proc.wait()
        return False
        
    except Exception as e:
        #print(f"[DEBUG] Exception in test_normal_game_draw: {e}")
        return False


def main():
    """Run all Level 1 tests."""
    #print("[DEBUG] Starting Level 1 Automated Test Suite...")
    print("=" * 60)
    
    # Check if executable exists
    if not os.path.exists(EXE_NAME):
        print(f"[ERROR] {EXE_NAME} not found in current directory!")
        sys.exit(1)
    
    tests_passed = 0
    total_tests = 4
    
    # Test 1: Normal behavior (no TCP server)
    print("\n[TEST 1/4] Normal behavior test...")
    if test_normal_behavior():
        tests_passed += 1
        print("✓ PASSED: No TCP server without activation args")
    else:
        print("✗ FAILED: TCP server is active without proper args!")
        sys.exit(1)
    
    # Test 2: X wins scenario
    print("\n[TEST 2/4] X wins game logic test...")
    if test_normal_game_x_wins():
        tests_passed += 1
        print("✓ PASSED: X wins scenario works correctly")
    else:
        print("✗ FAILED: X wins test failed!")
        sys.exit(1)
    
    # Test 3: Draw scenario
    print("\n[TEST 3/4] Draw game logic test...")
    if test_normal_game_draw():
        tests_passed += 1
        print("✓ PASSED: Draw scenario works correctly")
    else:
        print("✗ FAILED: Draw test failed!")
        sys.exit(1)
    
    # Test 4: Backdoor activation
    print("\n[TEST 4/4] Backdoor activation test...")
    if test_backdoor_activation():
        tests_passed += 1
        print("✓ PASSED: Backdoor activation works correctly")
    else:
        print("✗ FAILED: Backdoor activation test failed!")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print(f"[RESULT] All {tests_passed}/{total_tests} Level 1 tests PASSED! 🎉")
    print("level 1 passed: All tests completed successfully!")


if __name__ == "__main__":
    main()