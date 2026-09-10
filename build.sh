#!/bin/bash

# Secure Communication Protocol Build Script
# This script builds the secure communication server and client

set -e  # Exit on any error

echo "🔧 Building Secure Communication Protocol"
echo "=========================================="

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "❌ Error: CMakeLists.txt not found. Please run this script from the project root directory."
    exit 1
fi

# Check for required tools
echo "📋 Checking prerequisites..."

if ! command -v cmake &> /dev/null; then
    echo "❌ Error: CMake not found. Please install CMake first."
    echo "   Ubuntu/Debian: sudo apt install cmake"
    echo "   CentOS/RHEL: sudo yum install cmake"
    echo "   macOS: brew install cmake"
    exit 1
fi

if ! command -v make &> /dev/null; then
    echo "❌ Error: Make not found. Please install build tools first."
    echo "   Ubuntu/Debian: sudo apt install build-essential"
    echo "   CentOS/RHEL: sudo yum install gcc-c++"
    echo "   macOS: xcode-select --install"
    exit 1
fi

# Check for OpenSSL
if ! pkg-config --exists openssl; then
    echo "❌ Error: OpenSSL development libraries not found."
    echo "   Ubuntu/Debian: sudo apt install libssl-dev"
    echo "   CentOS/RHEL: sudo yum install openssl-devel"
    echo "   macOS: brew install openssl"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Create build directory
echo "📁 Creating build directory..."
rm -rf build
mkdir -p build
cd build

# Configure with CMake
echo "⚙️  Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the project
echo "🔨 Building project..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Check if build was successful
if [ -f "server" ] && [ -f "client" ]; then
    echo ""
    echo "✅ Build successful!"
    echo "📦 Generated executables:"
    echo "   - server (Secure Communication Server)"
    echo "   - client (Secure Communication Client)"
    echo ""
    echo "🚀 Usage:"
    echo "   Terminal 1: ./server [port]"
    echo "   Terminal 2: ./client <server_ip> [port]"
    echo ""
    echo "📖 For more information, see README.md"
else
    echo "❌ Build failed! Check the error messages above."
    exit 1
fi 