# intercli

An encrypted chat for people on the same network: a desktop app for Windows (and a
terminal client) where one person hosts a chat and others find it and join with a
room code. No internet connection is needed.

## 🛡️ Security Features

- **Encryption**: every message is encrypted with AES-256-GCM under keys from a fresh
  Diffie-Hellman exchange (ffdhe2048) for each connection.
- **Server identity**: the server proves who it is with an Ed25519 key, by signing
  each handshake. The app remembers each chat's key and refuses one that changes, and
  both sides can compare a 20-digit safety code.
- **Tamper and replay protection**: each frame's type, sequence number and session are
  bound into the encryption; altered, replayed, reordered or forged message and
  key-rotation frames end the connection. (Plain error notices from the server are not
  authenticated; someone on the network could show a fake "server error" line, but
  can't read or change messages that way.)
- **Key rotation**: each side changes the key it sends with every 10 messages (or on
  request), with an authenticated rotation marker.
- **Room codes**: a hosted chat needs its room code to join; wrong guesses are slowed
  down and locked out per address.
- **Saved messages** (optional): encrypted on disk with a key protected by your Windows
  account, and tied to the chat and name they belong to.

See [Security details](#-security-details) for how this works and what it doesn't cover.

## 📁 Project Structure

```
intercli/
├── CMakeLists.txt          # Build configuration
├── include/
│   └── common.h           # Shared data structures and constants
├── crypto/
│   ├── crypto_utils.h     # Cryptographic utilities header
│   └── crypto_utils.cpp   # Cryptographic implementation
├── server/
│   ├── core/              # Chat server library (server.exe and hosting in the app)
│   └── server.cpp         # Standalone server
├── client/
│   ├── core/              # Client protocol library shared by both clients
│   └── client.cpp         # Terminal client
├── gui/                   # Desktop app (Qt Quick), built when Qt 6 is found
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

### Build Instructions (Linux / macOS)

```bash
git clone https://github.com/obfdanso/intercli
cd intercli
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

On macOS with Homebrew, add `-DOPENSSL_ROOT_DIR="$(brew --prefix openssl)"` to the first
`cmake` command if CMake cannot find OpenSSL.

The programs are `build/server` and `build/client`.

### Building on Windows

Install [CMake](https://cmake.org/download/), Visual Studio (with the "Desktop development
with C++" workload) and [OpenSSL 3.x or newer for Win64](https://slproweb.com/products/Win32OpenSSL.html).
Then, from any terminal:

```bat
git clone https://github.com/obfdanso/intercli
cd intercli
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"
cmake --build build --config Release
```

The programs are `build\Release\server.exe` and `build\Release\client.exe`. The OpenSSL
DLLs are copied next to them during the build, so nothing needs adding to `PATH`.

### Building the desktop app (Windows)

The desktop app needs Qt 6.5 or newer as well. Install Qt 6.10 for MSVC 2022 64-bit
(the online installer, or `pip install aqtinstall` then
`python -m aqt install-qt windows desktop 6.10.3 win64_msvc2022_64 -O C:/Qt`) and tell
CMake where it is:

```bat
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" -DCMAKE_PREFIX_PATH="C:/Qt/6.10.3/msvc2022_64"
cmake --build build --config Release
```

The app is `build\Release\intercli.exe`. Qt's DLLs are deployed next to it during the
build. Without Qt, CMake prints `Qt6 not found: skipping the desktop app` and builds
everything else.

### Running the tests

Linux / macOS:
```bash
cd build && ctest --output-on-failure
```

Windows (Visual Studio builds need the configuration named):
```bat
cd build && ctest -C Release --output-on-failure
```

This runs the crypto unit tests (`dh_key_exchange`, `aes_gcm`, `identity`,
`chat_envelope`, `directional_keys`, `roster`), the server library test
(`server_core`, including room codes and lockouts), `chat_client` (real clients
against a real server, including tampered, replayed and injected frames through a
test proxy) and `chat_integration` (three terminal clients). With Qt installed it also
runs the desktop app's tests (`test_*`): models, the controller, saved messages,
the title bar, finding chats nearby and hosting. The tests that start a server need
`bash` (Git Bash on Windows) and are skipped where it isn't available.

## 🚀 Usage

### Chatting on the same Wi-Fi (desktop app)

Everyone needs to be on the same Wi-Fi, router or phone hotspot. No internet is needed.

1. **Host:** open intercli, type your name and click **Host a chat**. The app starts the
   chat on your PC and shows a **room code** (like `K7P-29Q`) in the details panel. The
   code stays the same every time you host, so share it once.
2. **Join:** everyone else opens intercli, types their name, picks your chat under
   **Chats nearby**, enters the room code and clicks **Join**. Their app remembers the
   code for next time.
3. If someone can't see the list (some networks block it), they can use **Join by
   address** with your PC's address (`ipconfig` shows it) and port 8080.

Good to know:
- The first time you host, Windows asks to let intercli through the firewall. Choose
  **Allow**, or nobody can join.
- On a network Windows calls **Public** (phone hotspots and new Wi-Fi often are),
  others can't reach you even after Allow. The app warns you; switch the network to
  Private in Settings > Network & internet.
- When the host signs out or closes the app, the chat ends for everyone (the app asks
  first).
- Compare the **safety code** in the details panel out loud with the host if you want
  to be sure nobody is in between.

### Starting the standalone server

```bash
./server
```

With no options, `server.exe` runs an open chat (no room code) on port 8080. It keeps its
identity key in `%APPDATA%\intercli\server.key` (protected by Windows for your user; on
Linux/macOS `~/.config/intercli/server.key`, owner-only) and prints its safety code when it
starts.

Options (`./server --help` lists them):

| Option | What it does | Default |
| --- | --- | --- |
| `--port N` | Port to listen on, 1-65535 | 8080 |
| `--room-code CODE` | Only people who know the code can join | open chat |
| `--max-wrong-codes N` | Wrong room codes allowed per address before a lockout | 10 |
| `--lockout SECONDS` | Length of the first lockout; each one after doubles, up to an hour | 60 |
| `--allow-global-ipv6 yes` | Take IPv6 connections from beyond the local network | no |
| `--log-level LEVEL` | `quiet`, `error` or `info` | `info` |
| `--log-file FILE` | Add log lines to a file instead of printing them | console |
| `--config FILE` | Read settings from a file | none |

```bash
./server --port 9000 --log-level error --log-file server.log
```

The room code can also be given in the `INTERCLI_ROOM_CODE` environment variable, which
keeps it off the command line where other programs on the PC could see it.

A config file has one `name = value` per line, named like the options without the dashes.
Options given after `--config` override the file:

```
# intercli.conf
port = 9000
room-code = ABC-234
log-level = info
log-file = server.log
```

Log lines carry the time and a level (`INFO` or `ERROR`). They say who connected and who
messaged whom, never what a message said.

### Connecting with the terminal client

```bash
./client <server_ip> [port]
```

**Example:**
```bash
./client 127.0.0.1 8080
./client ::1 8080          # IPv6 works too
```

The server listens on IPv4 and IPv6 at once. Over IPv6 it only takes connections from
this PC and the local network unless started with `--allow-global-ipv6 yes`, and room
code lockouts count a whole IPv6 network (/64) as one address. In the desktop app's "Join by address", an
IPv6 address with a port is written `[fe80::1]:8080`. Finding chats nearby still uses
IPv4 only.

It prints the server's safety code after connecting. To join a chat that has a room
code, set it in the environment first rather than on the command line, where other
programs could see it:

```bat
set INTERCLI_ROOM_CODE=K7P-29Q
client 192.168.1.20 8080
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

### Saved messages (desktop app)

The first time you sign in to a server with a name, the desktop app asks whether to
save your messages on this computer. If you choose **Don't Save**, nothing is written to
disk. If you choose **Save Messages**, your chats with that name on that server come back
the next time you sign in. You can change this later with the switch in the details
panel, and turning it off offers to delete what is already saved.

Saved messages are kept in `%APPDATA%\intercli\intercli\history.db`. The message text is
encrypted with AES-256-GCM under a key that Windows protects for your user account
(DPAPI), so another Windows user can't read it. Names aren't verified, though: anyone
using the same Windows account who signs in with the same name and server sees that
history.

### Who can read your messages

The host's server decrypts every message in order to route it, so the host can read
everything sent in their chat. Encryption protects messages from other people on the
network, not from the host. End-to-end encryption between users is not implemented.

## 🔐 Security details

### Handshake (protocol version 2)

1. The client sends a fresh Diffie-Hellman public key and a random nonce.
2. The server answers with its own fresh DH key and nonce, its Ed25519 identity key,
   and a signature over the session id, both DH keys and both nonces.
3. The client checks the signature. If it has joined this chat before, or the chat
   announced its key in the nearby list, the key must match, or the connection is
   refused before anything else is sent ("This chat's identity has changed").
4. Both sides derive separate send and receive keys from the DH secret and both nonces.

Older (version 1) clients or servers are refused with a message asking to update.

### Messages

- Each frame is encrypted with AES-256-GCM using a random 96-bit IV.
- The protocol version, frame type, sequence number and session id are authenticated
  as associated data, and sequence numbers must arrive strictly in order, so an
  altered, replayed, reordered or forged frame ends the connection.
- Every 10 messages (or when asked) each side rotates the key it sends with, announced
  by an encrypted rotation frame.

### Room codes

- Six characters from an alphabet without look-alikes, checked by the server before
  the name (so names can't be probed without the code), compared in constant time.
- Each wrong code waits a second; five on one connection close it; ten from one
  address lock that address out (for a minute, doubling each time, up to an hour).
  An address can have at most 8 connections that haven't joined.

### Finding chats nearby

- Joiners send a "who is hosting?" UDP query on port 8081 from a throwaway port; hosts
  answer only machines on their own networks, at most twice a second per sender, and
  queries are larger than answers so they can't be used to amplify traffic.
- The list ignores malformed answers, keeps a chat at the address it was first heard
  from, and is capped in size.

### Limits

- **First contact:** the very first join to a chat trusts the identity key the chat
  announces. Someone already on the network who answers faster than the real host
  could pose as it. Comparing safety codes out loud closes that gap.
- **The host reads everything** (see above). There is no end-to-end encryption.
- **Names aren't accounts:** anyone with the room code can join under any free name.
- **Saved messages** are readable by anyone using the same Windows account who signs
  in with the same name to the same chat.

## 🧪 Testing

### Basic Functionality Test
```bash
# Terminal 1: Start server
./server

# Terminal 2: Connect client
./client 127.0.0.1 8080
```

### Security checks covered by the tests
- Altered, replayed, injected and truncated frames (through a man-in-the-middle test proxy)
- A server proving a different identity than expected
- Wrong room codes, guessing across connections and in parallel, lockout and its end
- Spoofed, malformed and flooding discovery answers

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