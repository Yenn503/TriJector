# 💉 TriJector Project

A modular Windows loader demonstrating **three foundational process injection techniques**: Win32 API, NTAPI, and direct syscalls. TriJector was built for **educational research**, **malware analysis**, and **red team development**, and serves as a base for more advanced stealth injection loaders.

While this version is open-source for educational value, future enhanced builds with obfuscation, evasion, and encryption features will remain private for responsible usage.

---

### 🎯 Injection Technique Coverage

| Injection Method   | Status      |
|--------------------|-------------|
| Win32 API          | ✅ Implemented |
| NTAPI              | ✅ Implemented |
| Direct Syscalls    | ✅ Implemented |

---

## 🎯 Core Features

### 🧬 Injection Techniques
- Classic `CreateRemoteThread` via Win32 API
- Native `NtCreateThreadEx` (NTAPI)
- Direct syscall injection (x64)

### 🕵️ Stealth & Evasion Base
- Manual mapping potential
- Resource-based payload loading
- Clean memory mapping & zeroing
- Shellcode modularity

### 🧩 Modularity
- Each injection method separated for testing
- Easy integration into custom projects
- Supports msfvenom and raw shellcode

---

## 🚀 Components

### 1. Loader
- Multiple injection options via flags
- Payload loader from `.rsrc`
- Console output for method switching
- `/Loader` directory

### 2. Shellcode Support
- Raw shellcode injection support
- Compatible with `msfvenom` payloads
- Ready-to-use calc shellcode template
- `/Payloads` directory

---

## ⚙️ Building
1. Open `TriJector.sln`
2. Select `Release | x64` configuration
3. Build the full solution

---

## 📋 Requirements
- Windows 10+ x64
- Visual Studio 2019+ or MinGW
- `msfvenom` (for payload generation)
- Windows SDK + MASM (for syscall support)

---

## 🔄 Usage
1. Generate shellcode:  
   `msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin`
2. Embed shellcode into `.rsrc` section.
3. Compile TriJector with desired injection method.

---

## 📂 Project Structure

