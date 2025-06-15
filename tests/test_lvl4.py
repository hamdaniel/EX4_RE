import subprocess
import time
import psutil
import sys

def run_debugged_process():
    """Runs the debugged process and returns its proc."""
    exe_name = "tictactoe.exe"
    args = ["activate"]
    gdb_command = ["gdb", "--args", exe_name] + args
    # print(f"[DEBUG] Starting gdb subprocess with command: {gdb_command}")
    proc = subprocess.Popen(
        gdb_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # print(f"[DEBUG] gdb subprocess started with PID: {proc.pid}")
    time.sleep(2)

    # print("[DEBUG] Sending 'run' command to gdb stdin")
    proc.stdin.write("run\n")
    proc.stdin.flush()
    return proc

def get_child_pid(proc):
    gdb_proc = psutil.Process(proc.pid)

    for i in range(10):  # wait up to 5 seconds
        children = gdb_proc.children(recursive=False)
        if children:
            target_proc = children[0]
            # print(f"[DEBUG] Found debugged process PID: {target_proc.pid}")
            return target_proc
        else:
            # print(f"[DEBUG] Attempt {i+1}: No child process found yet, waiting...")
            time.sleep(0.5)
    return None

def open_ports_test(pid):
    """Returns True if the PID has any open TCP/UDP ports (listening or connected)."""
    time.sleep(4)  # Give some time for the process to start and open ports
    try:
        for _ in range(5):
            output = subprocess.check_output(["netstat", "-ano"], text=True)
            for line in output.splitlines():
                if line.strip().endswith(str(pid)):
                    return False # Failed test
            time.sleep(1)  # Wait before retrying
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] netstat failed: {e}")
    return True # Passed test

def normal_game_behavior_test(gdb_proc):
    moves = "1\n4\n2\n5\n3\n"
    
    try:
        gdb_proc.stdin.write(moves)
        gdb_proc.stdin.flush()
        time.sleep(1)  # Wait for the game to process the moves
        stdout, _ = gdb_proc.communicate(timeout=2)
        win_indicators = ["Player X wins!\n"]
        
        for indicator in win_indicators:
            if indicator in stdout:
                #print(f"[DEBUG] ✓ X wins test PASSED. Found: '{indicator}'")
                return True
        
        #print("[DEBUG] ✗ X wins test FAILED. No win message found.")
        return False
    except subprocess.TimeoutExpired:
        #print("[DEBUG] ✗ Game process timed out during X wins test")
        gdb_proc.kill()
        gdb_proc.wait()
        return False
        
    except Exception as e:
        #print(f"[DEBUG] Exception in test_normal_game_x_wins: {e}")
        return False
    
def main():
    # starts the debugged process under gdb
    gdb_proc = run_debugged_process()   
    tictactoe_proc = get_child_pid(gdb_proc)
    if not tictactoe_proc:
        print("[ERROR] Could not find tictactoe process")
        return


    failed_tests = False

    print("\n[TEST 1/2]")
    if open_ports_test(tictactoe_proc.pid):
        print("PASSED: No TCP server detected.")

    else:
        print("FAILED: Debugger detected suspicious activity.")
        failed_tests = True

    if not failed_tests:
        print("\n[TEST 2/2]")
        if normal_game_behavior_test(gdb_proc):
            print("PASSED: Expected game behavior")

        else:
            print("FAILED: Game behaves unexpectedly.")
            failed_tests = True
    if not failed_tests:
        print("\nLevel 4 passed!\n")

    # print("[DEBUG] Sending 'quit' command to gdb stdin")
    try:
        gdb_proc.stdin.write("quit\n")
        gdb_proc.stdin.flush()
        time.sleep(0.5)  # Let it process the quit
        gdb_proc.stdin.write("y\n")  # Confirm quit if needed
        gdb_proc.stdin.flush()
    except Exception as e:
        # print(f"[ERROR] Failed to send quit to gdb: {e}")
        pass

    # Optionally wait for gdb to terminate
    try:
        gdb_proc.wait(timeout=3)
        # print(f"[DEBUG] GDB exited with code {gdb_proc.returncode}")
    except subprocess.TimeoutExpired:
        # print(f"[WARN] GDB did not exit in time, killing...")
        gdb_proc.kill()

if __name__ == "__main__":
    main()
