import pefile

# === Configuration ===
exe_path = "tictactoe.exe"  # <- Path to the EXE to check
network_functions = [
    "WSAStartup",
    "WSACleanup",
    "socket",
    "bind",
    "listen",
    "accept",
    "recv",
    "send",
    "closesocket",
    "htons",
    "WSAGetLastError"
]

def check_imports(exe_path, function_list):
    try:
        pe = pefile.PE(exe_path)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return

    found = set()

    print("[TEST 1/1]")

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors='ignore').lower()
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode(errors='ignore')
                if func_name in function_list:
                    found.add(func_name)

    if found:
        print(f"Level 2 failed. found suspicious functions: {', '.join(found)}")
    else:
        print("Level 2 passed!")

if __name__ == "__main__":
    check_imports(exe_path, network_functions)
