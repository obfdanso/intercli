# C++ Compiler Installation Guide for Windows

## 🎯 Quick Solution

To build the Secure Communication Protocol, you need a C++ compiler. Here are the options:

### Option 1: Visual Studio Build Tools (Recommended)
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# After installation, run from Developer Command Prompt:
# Start Menu -> Visual Studio 2022 -> Developer Command Prompt
# Then navigate to your project and run: .\build.bat
```

### Option 2: MinGW-w64 (Alternative)
```powershell
# Download from: https://www.mingw-w64.org/downloads/
# Or use MSYS2: https://www.msys2.org/
```

### Option 3: Use Online Compiler (Temporary)
If you want to test the code immediately, you can use:
- **OnlineGDB**: https://www.onlinegdb.com/
- **Compiler Explorer**: https://godbolt.org/
- **Replit**: https://replit.com/

## 🔧 Manual Installation Steps

### Visual Studio Build Tools:
1. Go to: https://visualstudio.microsoft.com/downloads/
2. Download "Build Tools for Visual Studio 2022"
3. Run the installer
4. Select "C++ build tools" workload
5. Install
6. Open "Developer Command Prompt for VS 2022"
7. Navigate to your project: `cd C:\Users\HP\demo`
8. Run: `.\build.bat`

### MinGW-w64:
1. Go to: https://www.mingw-w64.org/downloads/
2. Download the latest version
3. Extract to `C:\mingw64`
4. Add `C:\mingw64\bin` to your PATH
5. Restart PowerShell
6. Run: `.\build.bat`

## 🚀 After Installing Compiler

Once you have a C++ compiler installed:

```powershell
# Build the project
.\build.bat

# Run the server
server.exe

# In another terminal, run the client
client.exe 127.0.0.1
```

## 📋 Current Status

- ✅ **CMake**: Installed and working
- ❌ **C++ Compiler**: Needs to be installed
- ✅ **Project Files**: Complete and ready
- ✅ **Build Scripts**: Ready to use

## 🎯 Next Steps

1. Install a C++ compiler using one of the methods above
2. Run `.\build.bat` to build the project
3. Start the server and client to test the secure communication

## 📖 More Information

- See `README.md` for detailed project information
- See `PROJECT_SUMMARY.md` for technical overview
- Run `.\demo_project.bat` to see project status 