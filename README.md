# Secure Communication Protocol

A comprehensive C++ implementation of a secure communication protocol with encryption, key exchange, forward secrecy, and authentication.

## 🛡️ Security Features

### Core Security Features
- **Message Encryption**: All messages are encrypted using AES-256-GCM
- **Key Exchange**: RSA-2048 and Diffie-Hellman key exchange for secure communication
- **Forward Secrecy**: Perfect Forward Secrecy (PFS) ensures past messages remain secure even if keys are compromised
- **Authentication**: Digital signatures and session verification
- **Key Rotation**: Automatic and manual key rotation for enhanced security

### Technical Implementation
- **RSA-2048**: For initial key exchange and digital signatures
- **Diffie-Hellman**: For ephemeral key generation and forward secrecy
- **AES-256-GCM**: For message encryption with authenticated encryption
- **SHA-256**: For hashing and HMAC generation
- **PBKDF2**: For key derivation with salt

## 📁 Project Structure

```
secure_comm/
├── CMakeLists.txt          # Build configuration
├── include/
│   └── common.h           # Shared data structures and constants
├── crypto/
│   ├── crypto_utils.h     # Cryptographic utilities header
│   └── crypto_utils.cpp   # Cryptographic implementation
├── server/
│   └── server.cpp         # Secure server implementation
├── client/
│   └── client.cpp         # Secure client implementation
├── tests/                 # Unit tests and the three-client integration test
└── README.md              # This file
```

## 🔧 Building the Project

### Prerequisites
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.10 or higher
- OpenSSL 3.x development libraries
- Linux, macOS, BSD, or Windows with MSVC

### Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

#### CentOS/RHEL/Fedora:
```bash
sudo yum install gcc-c++ cmake openssl-devel
# or for Fedora:
sudo dnf install gcc-c++ cmake openssl-devel
```

#### macOS:
```bash
brew install cmake openssl
```

### Build Instructions

1. **Clone and navigate to the project:**
```bash
cd secure_comm
```

2. **Create build directory:**
```bash
mkdir build && cd build
```

3. **Configure with CMake:**
```bash
cmake ..
```

4. **Build the project:**
```bash
make -j$(nproc)
```

5. **Install (optional):**
```bash
sudo make install
```

### Building on Windows (MSVC)

Build from a **Developer Command Prompt for VS**, or call `vcvars64.bat` first, so that
`cl.exe` is on the path. Point CMake at an OpenSSL 3.x installation with
`OPENSSL_ROOT_DIR`:

```bat
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"
cmake --build build
```

The OpenSSL runtime DLLs (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`) must sit next to the
executables or be on `PATH`.

### Running the tests

```bash
cd build && ctest --output-on-failure
```

This runs the `dh_key_exchange`, `aes_gcm`, `chat_envelope` and `directional_keys` unit
tests, plus `chat_integration`, which starts a real server and three clients (it needs
`bash`, and is skipped where bash is not available).

## 🚀 Usage

### Starting the Server

```bash
./server
```

The server takes no arguments and always listens on the default port (8080).

The server will:
- Generate RSA-2048 key pair
- Listen for client connections
- Perform secure handshakes
- Handle encrypted messages
- Automatically rotate keys every 10 messages

### Connecting with the Client

```bash
./client <server_ip> [port]
```

**Example:**
```bash
./client 127.0.0.1 8080
```

### Registering a name

After the handshake the client asks for a name, which is how other clients
address you. Names are 1 to 31 printable characters with no spaces. If the name
is already taken the server refuses it and you are asked again.

```
Enter your name: alice
Registered as alice
```

### Interactive Client Commands

| Input | Effect |
|---|---|
| `@bob hello` | Direct message to bob |
| `hello` | Broadcast to everyone else online |
| `/who` | List who is currently online |
| `rotate` | Rotate your send key |
| `quit` | Disconnect |

Your send key also rotates automatically after every 10 messages you send, as
does the server's.

Because input starting with `@` is read as a direct message, a broadcast cannot
begin with `@`. The protocol itself is unambiguous; this is only a property of
the typing shorthand.

**Example session:**
```
Enter your name: bob
Registered as bob

> /who
Online (3): alice, bob, carol

> hello everyone
> @alice just for you

> *** carol left ***
> quit
```

Meanwhile on alice's screen:
```
*** bob joined ***
[bob] hello everyone
[bob -> you] just for you
```

### Who can read your messages

The server decrypts every message in order to route it, so it can read all
relayed traffic. Encryption protects messages from a network observer, not from
the server operator. End-to-end encryption between clients is not implemented.

## 🔐 Security Protocol Details

### Handshake Process

1. **Client Init**: Client sends RSA public key and nonce
2. **Server Response**: Server generates DH key pair and sends public key
3. **Key Exchange**: Both parties perform DH key exchange
4. **Session Key**: Derive AES session key using shared secret and nonce
5. **Authentication**: Verify session and establish secure channel

### Message Encryption

1. **Generate IV**: Random initialization vector for each message
2. **Encrypt**: AES-256-GCM encryption with session key
3. **Sign**: Digital signature using RSA private key
4. **Send**: Transmit encrypted message with signature

### Forward Secrecy

- **Ephemeral Keys**: DH keys are generated per session
- **Key Rotation**: Automatic rotation every 10 messages
- **Manual Rotation**: Client can request key rotation anytime
- **Session Isolation**: Each session has unique keys

## 🛠️ API Overview

### CryptoManager Class
```cpp
// Key generation
KeyPair generate_rsa_keypair(size_t bits = 2048);
KeyPair generate_dh_keypair();

// Encryption/Decryption
std::vector<uint8_t> encrypt_aes_gcm(data, key, iv);
std::vector<uint8_t> decrypt_aes_gcm(encrypted_data, key, iv);

// Key exchange
std::vector<uint8_t> perform_dh_key_exchange(private_key, peer_public_key);
std::vector<uint8_t> derive_shared_secret(dh_result, salt);

// Digital signatures
std::vector<uint8_t> sign_data(data, private_key);
bool verify_signature(data, signature, public_key);
```

### SessionManager Class
```cpp
// Session management
SessionInfo create_session(uint32_t client_id);
SessionInfo get_session(uint32_t session_id);
void update_session_activity(uint32_t session_id);

// Authentication
bool authenticate_session(uint32_t session_id, auth_data);
AuthResult verify_session_auth(uint32_t session_id, signature);

// Key management
void set_session_key(uint32_t session_id, key);
std::vector<uint8_t> get_session_key(uint32_t session_id);
void rotate_session_key(uint32_t session_id);
```

## 🔍 Security Analysis

### Cryptographic Strength
- **RSA-2048**: 112-bit security level
- **AES-256**: 256-bit security level
- **SHA-256**: 128-bit collision resistance
- **DH-2048**: 112-bit security level

### Attack Resistance
- **Man-in-the-Middle**: Prevented by digital signatures
- **Replay Attacks**: Prevented by nonces and timestamps
- **Key Compromise**: Forward secrecy protects past messages
- **Session Hijacking**: Prevented by session authentication

### Best Practices Implemented
- **Constant-time operations**: For cryptographic comparisons
- **Secure random generation**: Using OpenSSL's RAND_bytes
- **Key rotation**: Regular key updates
- **Session expiration**: Automatic cleanup of old sessions
- **Error handling**: Secure error reporting without information leakage

## 🧪 Testing

### Basic Functionality Test
```bash
# Terminal 1: Start server
./server

# Terminal 2: Connect client
./client 127.0.0.1 8080
```

### Security Verification
- Check that messages are encrypted (use Wireshark)
- Verify key rotation works
- Test session expiration
- Confirm forward secrecy

## 📝 License

This project is provided as educational software. Use at your own risk in production environments.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## ⚠️ Disclaimer

This implementation is for educational purposes. For production use, consider:
- Additional security audits
- Integration with certificate authorities
- Hardware security modules (HSM)
- Regular security updates
- Compliance with relevant standards (FIPS, Common Criteria)

## 📚 References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Cryptographic Standards](https://www.nist.gov/cryptography)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446) 