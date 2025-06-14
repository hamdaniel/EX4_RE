import subprocess
import socket
import time
import os
import signal

EXE_NAME = "tictactoe.exe"
ACTIVATION_ARGS = ["123456", "activate", "gogogo"]
PORT = 6496
HOST = "127.0.0.1"
TEST_COMMAND = b"file open file.txt\n"
TIMEOUT = 5  # seconds

def run_exe_with_args(args):
    return subprocess.Popen([EXE_NAME] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_port_open(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, socket.timeout):
            return False

def wait_for_server(timeout=TIMEOUT):
    for _ in range(timeout * 10):
        if is_port_open(HOST, PORT):
            return True
        time.sleep(0.1)
    return False

def test_tcp_command():
    try:
        with socket.create_connection((HOST, PORT), timeout=2) as sock:
            sock.sendall(TEST_COMMAND)
            response = sock.recv(4096)
            if b"file.txt" in response:
                print("level 1 passed: TCP command executed successfully!")
                print("Response:", response.decode(errors="ignore"))
                return True
            else:
                return False
    except Exception as e:
        return False

def test_backdoor_activation():
    proc = run_exe_with_args(ACTIVATION_ARGS)
    time.sleep(1)
    if wait_for_server():
        test_tcp_command()
    else:
        return False
    proc.terminate()
    proc.wait()
    return True

def test_normal_behavior():
    proc = run_exe_with_args([])  # run with no args
    time.sleep(1)

    if is_port_open(HOST, PORT):
        proc.terminate()
        proc.wait()
        return False
    proc.terminate()
    proc.wait()
    return True

def test_normal_game_x_wins():
    proc = subprocess.Popen([EXE_NAME], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    moves = ["1\n", "4\n", "2\n", "5\n", "3\n"]  # X wins on top row
    output = ""
    for move in moves:
        proc.stdin.write(move)
        proc.stdin.flush()
        time.sleep(0.1)
        output += proc.stdout.read(200)  # read some output
        if "wins" in output:
            break
    proc.terminate()
    proc.wait()
    if "Player X wins" in output:
        return True
    else:
        return False

def test_normal_game_draw():
    proc = subprocess.Popen([EXE_NAME], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    moves = ["1\n", "2\n", "3\n", "5\n", "4\n", "6\n", "8\n", "7\n", "9\n"]  # Draw
    output = ""
    for move in moves:
        proc.stdin.write(move)
        proc.stdin.flush()
        time.sleep(0.1)
        output += proc.stdout.read(200)
        if "draw" in output:
            break
    proc.terminate()
    proc.wait()
    if "draw" in output.lower():
        return True
    else:
        return False

if __name__ == "__main__":
    if not test_normal_behavior():
        print("level 1 failed: TCP server is active without the proper args!")
        exit(1)
    if not test_normal_game_x_wins() or not test_normal_game_draw():
        print("level 1 failed: normal game test failed!")
        exit(1)
    if not test_backdoor_activation():
        print("level 1 failed: backdoor activation test failed!")
        exit(1)
