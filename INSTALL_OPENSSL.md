# OpenSSL Installation Guide for Windows

## 🎯 The Issue

Your build is failing because OpenSSL development libraries are missing. Here's how to fix it:

## 🔧 Solution Options

### Option 1: Install OpenSSL via vcpkg (Recommended)

```powershell
# Install vcpkg (C++ package manager)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install OpenSSL
.\vcpkg install openssl:x64-windows
```

### Option 2: Download OpenSSL Pre-built Binaries

1. **Go to**: https://slproweb.com/products/Win32OpenSSL.html
2. **Download**: "Win64 OpenSSL v3.x.x" (latest version)
3. **Install** it to `C:\OpenSSL-Win64`
4. **Set environment variables**:
   ```powershell
   setx OPENSSL_ROOT_DIR "C:\OpenSSL-Win64"
   setx OPENSSL_INCLUDE_DIR "C:\OpenSSL-Win64\include"
   setx OPENSSL_LIBRARIES "C:\OpenSSL-Win64\lib"
   ```

### Option 3: Use Chocolatey (if available)

```powershell
# Install Chocolatey first if not available
# Then install OpenSSL
choco install openssl
```

### Option 4: Manual Download and Setup

1. **Download** from: https://www.openssl.org/source/
2. **Extract** to `C:\openssl`
3. **Set environment variables**:
   ```powershell
   setx OPENSSL_ROOT_DIR "C:\openssl"
   ```

## 🚀 After Installing OpenSSL

1. **Restart** your command prompt
2. **Try building again**:
   ```cmd
   .\simple_build.bat
   ```

## 📋 Alternative: Use a Different Approach

If OpenSSL installation is complex, you can:

1. **Use WSL** (Windows Subsystem for Linux):
   ```bash
   sudo apt update
   sudo apt install libssl-dev
   ```

2. **Use Docker**:
   ```dockerfile
   FROM ubuntu:20.04
   RUN apt update && apt install -y libssl-dev build-essential cmake
   ```

3. **Use Online Compiler** for testing:
   - https://www.onlinegdb.com/
   - https://godbolt.org/

## 🎯 Quick Fix

The fastest solution is usually **Option 2** (pre-built binaries):

1. Download from: https://slproweb.com/products/Win32OpenSSL.html
2. Install to default location
3. Restart command prompt
4. Run: `.\simple_build.bat`

## 📖 Current Status

- ✅ **CMake**: Working
- ✅ **C++ Compiler**: Found (in Developer Command Prompt)
- ❌ **OpenSSL**: Missing (this is the current issue)
- ✅ **Project Files**: Complete

Once OpenSSL is installed, your secure communication protocol will build successfully! 