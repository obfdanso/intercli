@echo off
setlocal enabledelayedexpansion

echo Building Secure Communication Protocol
echo =====================================

REM Check if we're in the right directory
if not exist "CMakeLists.txt" (
    echo Error: CMakeLists.txt not found. Please run this script from the project root directory.
    pause
    exit /b 1
)

REM Check for required tools
echo Checking prerequisites...

where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: CMake not found. Please install CMake first.
    echo Download from: https://cmake.org/download/
    pause
    exit /b 1
)

REM Check for C++ compiler
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo Warning: Visual Studio C++ compiler (cl) not found in PATH.
    echo Trying to find alternative compilers...
    
    REM Try to find g++ (MinGW)
    where g++ >nul 2>&1
    if %errorlevel% neq 0 (
        echo Error: No C++ compiler found. Please install one of the following:
        echo 1. Visual Studio Build Tools (recommended for Windows)
        echo 2. MinGW-w64
        echo 3. Or run from Visual Studio Developer Command Prompt
        pause
        exit /b 1
    ) else (
        echo Found g++ compiler
        set CMAKE_GENERATOR=MinGW Makefiles
    )
) else (
    echo Found Visual Studio C++ compiler
    set CMAKE_GENERATOR=Visual Studio 17 2022
)

echo Prerequisites check passed

REM Create build directory
echo Creating build directory...
if exist build rmdir /s /q build
mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
if defined CMAKE_GENERATOR (
    cmake .. -G "%CMAKE_GENERATOR%" -DCMAKE_BUILD_TYPE=Release
) else (
    cmake .. -DCMAKE_BUILD_TYPE=Release
)
if %errorlevel% neq 0 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

REM Build the project
echo Building project...
if defined CMAKE_GENERATOR (
    if "%CMAKE_GENERATOR%"=="Visual Studio 17 2022" (
        cmake --build . --config Release
    ) else (
        cmake --build .
    )
) else (
    cmake --build .
)
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

REM Check if build was successful
if exist "server.exe" if exist "client.exe" (
    echo.
    echo Build successful!
    echo Generated executables:
    echo - server.exe (Secure Communication Server)
    echo - client.exe (Secure Communication Client)
    echo.
    echo Usage:
    echo Terminal 1: server.exe [port]
    echo Terminal 2: client.exe [server_ip] [port]
    echo.
    echo For more information, see README.md
) else if exist "Release\server.exe" if exist "Release\client.exe" (
    echo.
    echo Build successful!
    echo Generated executables:
    echo - Release\server.exe (Secure Communication Server)
    echo - Release\client.exe (Secure Communication Client)
    echo.
    echo Usage:
    echo Terminal 1: Release\server.exe [port]
    echo Terminal 2: Release\client.exe [server_ip] [port]
    echo.
    echo For more information, see README.md
) else if exist "Debug\server.exe" if exist "Debug\client.exe" (
    echo.
    echo Build successful!
    echo Generated executables:
    echo - Debug\server.exe (Secure Communication Server)
    echo - Debug\client.exe (Secure Communication Client)
    echo.
    echo Usage:
    echo Terminal 1: Debug\server.exe [port]
    echo Terminal 2: Debug\client.exe [server_ip] [port]
    echo.
    echo For more information, see README.md
) else (
    echo Build failed! Check the error messages above.
    pause
    exit /b 1
)

cd ..
pause 