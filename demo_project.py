#!/usr/bin/env python3
"""
Secure Communication Protocol - Project Demo
============================================

This script demonstrates the project structure and provides information
about how to build and run the secure communication protocol.
"""

import os
import sys
import subprocess
import time
import json

def print_header():
    print("🔐 Secure Communication Protocol")
    print("=" * 50)
    print("Project Demo and Information")
    print()

def check_project_structure():
    print("📁 Project Structure Check:")
    print("-" * 30)
    
    required_files = [
        "CMakeLists.txt",
        "include/common.h",
        "crypto/crypto_utils.h",
        "crypto/crypto_utils.cpp",
        "server/server.cpp",
        "client/client.cpp",
        "README.md",
        "build.bat",
        "build_vs.bat"
    ]
    
    all_present = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            all_present = False
    
    print()
    return all_present

def check_tools():
    print("🔧 Tool Availability Check:")
    print("-" * 30)
    
    tools = {
        "cmake": "CMake build system",
        "cl": "Visual Studio C++ compiler",
        "g++": "GNU C++ compiler",
        "make": "Make build tool"
    }
    
    available_tools = []
    for tool, description in tools.items():
        try:
            result = subprocess.run([tool, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {tool} - {description}")
                available_tools.append(tool)
            else:
                print(f"❌ {tool} - {description}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"❌ {tool} - {description}")
    
    print()
    return available_tools

def show_project_info():
    print("📋 Project Information:")
    print("-" * 30)
    
    info = {
        "Project Name": "Secure Communication Protocol",
        "Language": "C++17",
        "Cryptography": "OpenSSL",
        "Network": "TCP Sockets",
        "Build System": "CMake",
        "Security Features": [
            "RSA-2048 key exchange",
            "Diffie-Hellman forward secrecy",
            "AES-256-GCM encryption",
            "Digital signatures",
            "Key rotation",
            "Session management"
        ]
    }
    
    for key, value in info.items():
        if isinstance(value, list):
            print(f"{key}:")
            for item in value:
                print(f"  • {item}")
        else:
            print(f"{key}: {value}")
    
    print()

def show_usage_instructions():
    print("🚀 Usage Instructions:")
    print("-" * 30)
    
    print("1. Build the project:")
    print("   • Windows: .\\build.bat or .\\build_vs.bat")
    print("   • Linux/macOS: ./build.sh")
    print()
    
    print("2. Run the server:")
    print("   • server.exe [port]")
    print("   • Default port: 8080")
    print()
    
    print("3. Run the client:")
    print("   • client.exe <server_ip> [port]")
    print("   • Example: client.exe 127.0.0.1 8080")
    print()
    
    print("4. Interactive client commands:")
    print("   • Type messages to send encrypted data")
    print("   • 'rotate' - Request key rotation")
    print("   • 'quit' or 'exit' - Close client")
    print()

def show_security_features():
    print("🔒 Security Features:")
    print("-" * 30)
    
    features = [
        ("Key Exchange", "RSA-2048 for initial key exchange, Diffie-Hellman for forward secrecy"),
        ("Encryption", "AES-256-GCM for authenticated encryption"),
        ("Authentication", "Digital signatures using RSA-2048"),
        ("Forward Secrecy", "Automatic key rotation every 10 messages"),
        ("Session Management", "Secure session tracking and authentication"),
        ("Random Generation", "Cryptographically secure random number generation"),
        ("Key Derivation", "PBKDF2 for secure key derivation"),
        ("Message Integrity", "HMAC-SHA256 for message authentication")
    ]
    
    for feature, description in features:
        print(f"• {feature}: {description}")
    
    print()

def show_protocol_flow():
    print("🔄 Protocol Flow:")
    print("-" * 30)
    
    steps = [
        "1. Client connects to server",
        "2. Handshake initiation (RSA key exchange)",
        "3. Diffie-Hellman key exchange for forward secrecy",
        "4. Session key derivation using PBKDF2",
        "5. Secure message exchange using AES-256-GCM",
        "6. Automatic key rotation for forward secrecy",
        "7. Digital signature verification for authentication"
    ]
    
    for step in steps:
        print(step)
    
    print()

def main():
    print_header()
    
    # Check project structure
    structure_ok = check_project_structure()
    
    # Check available tools
    available_tools = check_tools()
    
    # Show project information
    show_project_info()
    
    # Show security features
    show_security_features()
    
    # Show protocol flow
    show_protocol_flow()
    
    # Show usage instructions
    show_usage_instructions()
    
    # Summary
    print("📊 Summary:")
    print("-" * 30)
    
    if structure_ok:
        print("✅ Project structure is complete")
    else:
        print("❌ Some project files are missing")
    
    if available_tools:
        print(f"✅ Found {len(available_tools)} build tools: {', '.join(available_tools)}")
        if 'cmake' in available_tools:
            print("✅ CMake is available - you can build the project!")
        else:
            print("❌ CMake is not available")
    else:
        print("❌ No build tools found")
        print("💡 To build this project, you need:")
        print("   • CMake (✅ already installed)")
        print("   • A C++ compiler (Visual Studio, MinGW, or GCC)")
        print("   • OpenSSL development libraries")
    
    print()
    print("🎯 Next Steps:")
    print("1. Install a C++ compiler if not available")
    print("2. Run the build script: .\\build.bat")
    print("3. Start the server: server.exe")
    print("4. Connect with client: client.exe 127.0.0.1")
    print()
    print("📖 For detailed information, see README.md")

if __name__ == "__main__":
    main() 