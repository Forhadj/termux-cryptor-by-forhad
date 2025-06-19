#!/usr/bin/env python3

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import md5, sha256
import argparse
import os

# ───── ASCII BANNER ─────
print(r"""
  _____ ___  ____  _   _    _    ____  
 |  ___/ _ \|  _ \| | | |  / \  |  _ \ 
 | |_ | | | | |_) | |_| | / _ \ | | | |
 |  _|| |_| |  _ <|  _  |/ ___ \| |_| |
 |_|   \___/|_| \_\_| |_/_/   \_\____/ 
                                       
         🔐 Termux Secure Suite by Forhad
""")

# ───── FUNCTIONS ─────

def encrypt_file_aes(filename, manual_key=None, delete_original=False):
    key = manual_key.encode().ljust(32, b'0') if manual_key else get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filename, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(filename + ".aes", 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)
    if delete_original:
        os.remove(filename)
    print("✅ AES encryption done.")
    if manual_key:
        print("[!] Manual key used, save securely.")
    else:
        print(f"🔑 Auto key: {key.hex()}")

def decrypt_file_aes(filename, manual_key=None):
    with open(filename, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    key = manual_key.encode().ljust(32, b'0') if manual_key else input("🔑 Enter 32-byte key (hex): ").encode()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    outname = filename.replace(".aes", ".dec")
    with open(outname, 'wb') as f:
        f.write(data)
    print(f"✅ AES decryption done. Output: {outname}")

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", 'wb') as f:
        f.write(private_key)
    with open("public.pem", 'wb') as f:
        f.write(public_key)
    print("✅ RSA keypair generated: private.pem / public.pem")

def rsa_encrypt_file(filename, pubkey_file):
    with open(pubkey_file, 'rb') as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    with open(filename, 'rb') as f:
        data = f.read()
    encrypted = cipher.encrypt(data)
    with open(filename + ".enc", 'wb') as f:
        f.write(encrypted)
    print("✅ RSA encryption done.")

def rsa_decrypt_file(filename, privkey_file):
    with open(privkey_file, 'rb') as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    with open(filename, 'rb') as f:
        encrypted = f.read()
    data = cipher.decrypt(encrypted)
    with open(filename.replace(".enc", ".dec"), 'wb') as f:
        f.write(data)
    print("✅ RSA decryption done.")

def hash_file(filename, method='md5'):
    h = md5() if method == 'md5' else sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    print(f"🔍 {method.upper()} hash: {h.hexdigest()}")

# ───── CLI HANDLER ─────
parser = argparse.ArgumentParser(description="🔐 Termux Secure Suite by Forhad")
sub = parser.add_subparsers(dest='cmd')

enc = sub.add_parser('encrypt')
enc.add_argument('filename')
enc.add_argument('--aes', action='store_true')
enc.add_argument('--rsa')
enc.add_argument('--manual-key')
enc.add_argument('--delete', action='store_true')

dec = sub.add_parser('decrypt')
dec.add_argument('filename')
dec.add_argument('--aes', action='store_true')
dec.add_argument('--rsa')
dec.add_argument('--manual-key')

rsa_keygen = sub.add_parser('rsa-genkey')

hasher = sub.add_parser('hash')
hasher.add_argument('filename')
hasher.add_argument('--sha256', action='store_true')

args = parser.parse_args()

if args.cmd == 'encrypt':
    if args.aes:
        encrypt_file_aes(args.filename, args.manual_key, args.delete)
    elif args.rsa:
        rsa_encrypt_file(args.filename, args.rsa)
    else:
        print("❌ Choose --aes or --rsa <pubkey.pem>")

elif args.cmd == 'decrypt':
    if args.aes:
        decrypt_file_aes(args.filename, args.manual_key)
    elif args.rsa:
        rsa_decrypt_file(args.filename, args.rsa)
    else:
        print("❌ Choose --aes or --rsa <privkey.pem>")

elif args.cmd == 'rsa-genkey':
    generate_rsa_keys()

elif args.cmd == 'hash':
    method = 'sha256' if args.sha256 else 'md5'
    hash_file(args.filename, method)

else:
    parser.print_help()
