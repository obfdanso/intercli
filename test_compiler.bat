@echo off
echo Testing for C++ compilers...
echo.

echo Looking for Visual Studio compiler (cl.exe)...
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo FOUND: Visual Studio C++ compiler
    cl
) else (
    echo NOT FOUND: Visual Studio C++ compiler
)

echo.
echo Looking for MinGW compiler (g++.exe)...
where g++ >nul 2>&1
if %errorlevel% equ 0 (
    echo FOUND: MinGW C++ compiler
    g++ --version
) else (
    echo NOT FOUND: MinGW C++ compiler
)

echo.
echo Looking for GCC compiler (gcc.exe)...
where gcc >nul 2>&1
if %errorlevel% equ 0 (
    echo FOUND: GCC compiler
    gcc --version
) else (
    echo NOT FOUND: GCC compiler
)

echo.
echo SOLUTION: You need to install a C++ compiler or use Developer Command Prompt
echo.
pause 