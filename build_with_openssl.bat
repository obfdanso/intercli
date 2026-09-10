@echo off
echo 🔐 Building Secure Communication Protocol with OpenSSL
echo =====================================================

REM Set OpenSSL environment variables
set OPENSSL_ROOT_DIR=C:\Program Files\OpenSSL-Win64
set OPENSSL_INCLUDE_DIR=C:\Program Files\OpenSSL-Win64\include
set OPENSSL_LIBRARIES=C:\Program Files\OpenSSL-Win64\lib
set PATH=%PATH%;C:\Program Files\OpenSSL-Win64\bin

echo ✅ OpenSSL environment variables set
echo.

REM Check if build directory exists, create if not
if not exist build mkdir build
cd build

echo 🔧 Configuring with CMake...
cmake .. -G "Visual Studio 17 2022"

if %ERRORLEVEL% NEQ 0 (
    echo ❌ CMake configuration failed!
    pause
    exit /b 1
)

echo ✅ CMake configuration successful
echo.

echo 🔨 Building project...
cmake --build . --config Release

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo.
echo 🎉 Build successful!
echo.
echo 📁 Generated executables:
if exist Release\server.exe (
    echo - Release\server.exe (Secure Communication Server)
)
if exist Release\client.exe (
    echo - Release\client.exe (Secure Communication Client)
)
echo.

echo 🚀 To run the project:
echo 1. Start the server: Release\server.exe
echo 2. Connect with client: Release\client.exe 127.0.0.1
echo.

pause 