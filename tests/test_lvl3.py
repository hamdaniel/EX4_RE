import pefile


# === Configuration ===
exe_path = "tictactoe.exe"  # <- Path to the EXE to check
network_functions = [
    "ws2_32.dll",
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

def extract_ascii_strings(data, min_len=4):
    strings = []
    current = b""

    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append(current.decode(errors='ignore'))
            current = b""
    if len(current) >= min_len:
        strings.append(current.decode(errors='ignore'))
    return strings

def check_strings_section(exe_path, keywords):
    try:
        pe = pefile.PE(exe_path)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return

    found = set()
    all_strings = []

    print("[TEST 1/1]")

    for section in pe.sections:
        name = section.Name.decode(errors='ignore').rstrip('\x00')
        if name in ['.rdata', '.data', '.text', '.idata']:  # check strings in typical string-holding sections
            try:
                data = section.get_data()
                strings = extract_ascii_strings(data)
                all_strings.extend(strings)
            except Exception:
                continue

    for s in all_strings:
        for keyword in keywords:
            if keyword in s:
                found.add(keyword)

    if found:
        print(f"\nLevel 3 failed. found suspicious string found: {', '.join(sorted(found))}\n")
    else:
        print("\nLevel 3 passed!\n")

if __name__ == "__main__":
    check_strings_section(exe_path, network_functions)
