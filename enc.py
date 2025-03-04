import sys
import os

def xor_encrypt(data, key):
    return bytes(byte ^ key for byte in data)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python enc.py <shellcode.bin> <key>")
        sys.exit(1)

    shellcode_file = sys.argv[1]
    key = int(sys.argv[2]) & 0xFF

    if not os.path.exists(shellcode_file):
        print(f"error: file {shellcode_file} not exist")
        sys.exit(1)

    with open(shellcode_file, "rb") as f:
        shellcode = f.read()

    encrypted_shellcode = xor_encrypt(shellcode, key)
    encrypted_file = f"{shellcode_file}.enc"
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_shellcode)

    print(f"Shellcode saved in {encrypted_file}")