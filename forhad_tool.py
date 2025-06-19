import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_file(file_path):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, 'rb') as f:
        data = f.read()

    ct = cipher.encrypt(pad(data, AES.block_size))

    with open(file_path + ".aes", 'wb') as f:
        f.write(cipher.iv + ct)

    with open("key_for_" + file_path + ".key", "wb") as f:
        f.write(key)

    print(f"[✓] Encrypted: {file_path}.aes")
    print(f"[✓] Key saved: key_for_{file_path}.key")

def decrypt_file(file_path):
    key_file = "key_for_" + file_path.replace(".aes", "") + ".key"

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
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    output_file = file_path.replace(".aes", "") + "_decrypted.txt"
    with open(output_file, 'wb') as f:
        f.write(pt)

    print(f"[✓] Decrypted: {output_file}")

# === CLI Usage ===
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python forhad_tool.py encrypt filename")
        print("  python forhad_tool.py decrypt filename.aes")
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]

    if action == "encrypt":
        encrypt_file(filename)
    elif action == "decrypt":
        decrypt_file(filename)
    else:
        print("Invalid command. Use 'encrypt' or 'decrypt'.")
