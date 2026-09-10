@echo off

echo Building Secure Communication Protocol
echo =====================================

echo Checking prerequisites...

where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: CMake not found. Please install CMake first.
    pause
    exit /b 1
)

echo CMake found!

where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo Warning: Visual Studio C++ compiler not found.
    echo Please install Visual Studio Build Tools or use Developer Command Prompt.
    pause
    exit /b 1
)

echo C++ compiler found!

echo Creating build directory...
if exist build rmdir /s /q build
mkdir build
cd build

echo Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

echo Building project...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Build completed!
pause 