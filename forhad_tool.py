
import sys, os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def show_banner():
    print(r"""
 ______               _               _ 
|  ____|             | |             | |
| |__ _ __ ___  _ __ | | ___  _   _  | |
|  __| '__/ _ \| '_ \| |/ _ \| | | | | |
| |  | | | (_) | |_) | | (_) | |_| | |_|
|_|  |_|  \___/| .__/|_|\___/ \__,_| (_)
               | |                      
               |_|      🔐 By Forhad    
""")

def encrypt_file(file_path, use_manual_key=False, auto_delete=False):
    if use_manual_key:
        key_input = input("[?] Enter 16-character key: ").strip()
        if len(key_input) != 16:
            print("[X] Key must be 16 characters long!")
            return
        key = key_input.encode()
    else:
        key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, 'rb') as f:
        data = f.read()

    ct = cipher.encrypt(pad(data, AES.block_size))

    with open(file_path + ".aes", 'wb') as f:
        f.write(cipher.iv + ct)

    with open("key_for_" + os.path.basename(file_path) + ".key", "wb") as f:
        f.write(key)

    print(f"[✓] Encrypted: {file_path}.aes")
    print(f"[✓] Key saved as: key_for_{os.path.basename(file_path)}.key")

    if auto_delete:
        os.remove(file_path)
        print(f"[i] Original file '{file_path}' deleted.")

def decrypt_file(file_path, use_manual_key=False):
    key_file = "key_for_" + os.path.basename(file_path).replace(".aes", "") + ".key"

    if use_manual_key:
        key_input = input("[?] Enter 16-character key: ").strip()
        if len(key_input) != 16:
            print("[X] Key must be 16 characters!")
            return
        key = key_input.encode()
    else:
        try:
            with open(key_file, 'rb') as f:
                key = f.read()
        except FileNotFoundError:
            print("[X] Key file not found!")
            return

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ct = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
    except ValueError:
        print("[X] Decryption failed. Wrong key?")
        return

    output_file = file_path.replace(".aes", "") + "_decrypted.txt"
    with open(output_file, 'wb') as f:
        f.write(pt)

    print(f"[✓] Decrypted: {output_file}")

def show_help():
    print("Usage:")
    print("  python forhad_tool.py encrypt filename [--manual-key] [--delete]")
    print("  python forhad_tool.py decrypt filename.aes [--manual-key]")

if __name__ == "__main__":
    show_banner()

    if len(sys.argv) < 3:
        show_help()
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]
    use_manual_key = "--manual-key" in sys.argv
    auto_delete = "--delete" in sys.argv

    if action == "encrypt":
        encrypt_file(filename, use_manual_key, auto_delete)
    elif action == "decrypt":
        decrypt_file(filename, use_manual_key)
    else:
        show_help()
