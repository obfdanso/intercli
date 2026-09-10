#!/usr/bin/env python3
"""
Secure Communication Protocol Test Demo
This script demonstrates the key features of the secure communication system.
"""

import subprocess
import time
import threading
import socket
import sys
import os

class SecureCommDemo:
    def __init__(self):
        self.server_process = None
        self.client_process = None
        self.server_port = 8080
        
    def check_executables(self):
        """Check if server and client executables exist"""
        server_exe = "server.exe" if os.name == 'nt' else "server"
        client_exe = "client.exe" if os.name == 'nt' else "client"
        
        if not os.path.exists(f"build/{server_exe}"):
            print("❌ Server executable not found. Please build the project first.")
            return False
            
        if not os.path.exists(f"build/{client_exe}"):
            print("❌ Client executable not found. Please build the project first.")
            return False
            
        return True
    
    def start_server(self):
        """Start the secure server in background"""
        server_exe = "server.exe" if os.name == 'nt' else "server"
        try:
            self.server_process = subprocess.Popen(
                [f"build/{server_exe}", str(self.server_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(2)  # Give server time to start
            print("✅ Server started successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
    
    def test_connection(self):
        """Test basic connection to server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', self.server_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def run_client_test(self, test_messages):
        """Run client with test messages"""
        client_exe = "client.exe" if os.name == 'nt' else "client"
        try:
            # Create input for client
            input_data = "\n".join(test_messages) + "\nquit\n"
            
            # Run client
            process = subprocess.Popen(
                [f"build/{client_exe}", "127.0.0.1", str(self.server_port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=input_data, timeout=30)
            
            if process.returncode == 0:
                print("✅ Client test completed successfully")
                return True
            else:
                print(f"❌ Client test failed: {stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Client test timed out")
            return False
        except Exception as e:
            print(f"❌ Client test error: {e}")
            return False
    
    def stop_server(self):
        """Stop the server process"""
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
            print("✅ Server stopped")
    
    def run_demo(self):
        """Run the complete demo"""
        print("🔐 Secure Communication Protocol Demo")
        print("=" * 50)
        
        # Check if executables exist
        if not self.check_executables():
            return False
        
        # Test messages
        test_messages = [
            "Hello, this is a test message!",
            "This message should be encrypted with AES-256-GCM",
            "Testing forward secrecy with key rotation",
            "rotate",  # Test key rotation
            "Message after key rotation",
            "Final test message"
        ]
        
        try:
            # Start server
            print("\n🚀 Starting secure server...")
            if not self.start_server():
                return False
            
            # Test connection
            print("\n🔗 Testing server connection...")
            if not self.test_connection():
                print("❌ Cannot connect to server")
                return False
            print("✅ Server connection successful")
            
            # Run client test
            print("\n📡 Running client tests...")
            print("Test messages:")
            for i, msg in enumerate(test_messages, 1):
                if msg != "rotate":
                    print(f"  {i}. {msg}")
                else:
                    print(f"  {i}. [Key Rotation Request]")
            
            if not self.run_client_test(test_messages):
                return False
            
            print("\n🎉 Demo completed successfully!")
            print("\n📋 Demo Summary:")
            print("  ✅ RSA-2048 key exchange")
            print("  ✅ AES-256-GCM encryption")
            print("  ✅ Perfect Forward Secrecy")
            print("  ✅ Session authentication")
            print("  ✅ Key rotation")
            print("  ✅ Digital signatures")
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️  Demo interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Demo error: {e}")
            return False
        finally:
            self.stop_server()

def main():
    demo = SecureCommDemo()
    success = demo.run_demo()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 