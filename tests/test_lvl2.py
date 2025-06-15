import pefile

# === Configuration ===
exe_path = "tictactoe.exe"  # <- Path to the EXE to check
network_dlls = [
    "ws2_32.dll",
    "wininet.dll",
    "winhttp.dll",
    "dnsapi.dll",
    "iphlpapi.dll",
    "urlmon.dll",
    "netapi32.dll",
    "rasapi32.dll"
]

def check_network_dll_imports(exe_path, dll_list):
    try:
        pe = pefile.PE(exe_path)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("No import table found.")
        return

    imported_dlls = [entry.dll.decode(errors='ignore').lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]

    found = [dll for dll in imported_dlls if dll in dll_list]

    print("[TEST 1/1]")

    if found:
        print(f"\nLevel 2 failed. Found suspicious network DLLs: {', '.join(found)}\n")
    else:
        print("\nLevel 2 passed!\n")

if __name__ == "__main__":
    check_network_dll_imports(exe_path, network_dlls)
