@echo off
setlocal enabledelayedexpansion

echo 🔧 Building Secure Communication Protocol with Visual Studio
echo =============================================================

REM Set up Visual Studio environment
echo 📋 Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\vsdevcmd\ext\vcvars.bat"

REM Check if we're in the right directory
if not exist "CMakeLists.txt" (
    echo ❌ Error: CMakeLists.txt not found. Please run this script from the project root directory.
    exit /b 1
)

REM Check for required tools
echo 📋 Checking prerequisites...

where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: CMake not found. Please install CMake first.
    exit /b 1
)

where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Visual Studio C++ compiler not found after environment setup.
    exit /b 1
)

echo ✅ Prerequisites check passed

REM Create build directory
echo 📁 Creating build directory...
if exist build rmdir /s /q build
mkdir build
cd build

REM Configure with CMake
echo ⚙️  Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo ❌ CMake configuration failed!
    exit /b 1
)

REM Build the project
echo 🔨 Building project...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo ❌ Build failed!
    exit /b 1
)

REM Check if build was successful
if exist "Release\server.exe" if exist "Release\client.exe" (
    echo.
    echo ✅ Build successful!
    echo 📦 Generated executables:
    echo    - Release\server.exe (Secure Communication Server)
    echo    - Release\client.exe (Secure Communication Client)
    echo.
    echo 🚀 Usage:
    echo    Terminal 1: Release\server.exe [port]
    echo    Terminal 2: Release\client.exe ^<server_ip^> [port]
    echo.
    echo 📖 For more information, see README.md
) else (
    echo ❌ Build failed! Check the error messages above.
    exit /b 1
)

cd .. 