
# 🔐 termux-cryptor-by-forhad

A lightweight AES-based file encryption and decryption tool designed for **Termux** users.

> Developed with ❤️ by [Forhad](https://github.com/Forhadj)

---

## ⚙️ Features

- ✅ AES-128 bit secure encryption
- ✅ Manual key input or random key generation
- ✅ Auto-delete original file option
- ✅ Fully works in Termux or Linux

---

## 🚀 Installation

```bash
pkg update
pkg install python -y
pip install pycryptodome
```

---

## 📦 Usage

### 🔐 Encrypt a file

```bash
python forhad_tool.py encrypt myfile.txt
```

### 🔐 Encrypt with manual key & delete original

```bash
python forhad_tool.py encrypt myfile.txt --manual-key --delete
```

### 🔓 Decrypt a file

```bash
python forhad_tool.py decrypt myfile.txt.aes
```

### 🔓 Decrypt with manual key input

```bash
python forhad_tool.py decrypt myfile.txt.aes --manual-key
```

---

## ⚠️ WARNING

- 🔑 Don't lose the `.key` file — without it you can't decrypt!
- 📂 Keep encrypted files and keys safe from others.

---

## 👨‍💻 Developer

- GitHub: [@Forhadj](https://github.com/Forhadj)
