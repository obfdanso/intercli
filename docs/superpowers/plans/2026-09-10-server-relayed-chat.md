# Server-Relayed Chat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let SecureComm clients register a name and exchange direct and broadcast messages through the server, with key rotation that stays correct while relayed messages are in flight.

**Architecture:** A structured `ChatMessage` envelope travels inside the existing AES-GCM ciphertext, so the outer framing and crypto layer are untouched. The server keeps a name-to-connection registry and routes decrypted envelopes. Each session holds a pair of directional keys (`tx_key`/`rx_key`), each rotated only by its owner and announced in-band on the stream it governs.

**Tech Stack:** C++17, OpenSSL 3.x (EVP), Winsock2/POSIX sockets, CMake + Ninja, ctest.

**Spec:** `docs/superpowers/specs/2026-09-10-server-relayed-chat-design.md`

## Global Constraints

- C++17. Compiles under MSVC `/W4` and GCC/Clang `-Wall -Wextra -Wpedantic`.
- OpenSSL 3.x only. No deprecated low-level `DH_*` / `RSA_*` APIs.
- `MAX_NAME_LEN = 32`, `MAX_TEXT_LEN = 1024`. `sizeof(ChatMessage)` must stay under `MAX_MESSAGE_SIZE - GCM_TAG_SIZE` (4080 bytes).
- Names: 1 to 31 characters, printable ASCII, no whitespace.
- `text_len` greater than `MAX_TEXT_LEN` is rejected. Never truncate.
- The `sender` field is stamped by the server from its registry and ignored on inbound messages.
- **Never hold `registry_mutex_` during socket I/O.** Copy the `shared_ptr`, release the lock, then send.
- **Every send to a connection takes that connection's `send_mutex`, with encryption inside the lock.**
- A peer rotates only its own `tx_key`, after every 10 messages it sends, announced in-band.
- All structs crossing the wire are inside the existing `#pragma pack(push, 1)` region of `common.h`.

## Build and test commands

All build commands assume a Developer Command Prompt, or `vcvars64.bat` called first. From the repo root:

```bash
cmake -G Ninja -S . -B build_fix -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="C:/Program Files/PostgreSQL/18"
cmake --build build_fix
cd build_fix && ctest --output-on-failure
```

The OpenSSL DLLs must sit beside the executables:

```bash
cp "C:/Program Files/PostgreSQL/18/bin/libcrypto-3-x64.dll" build_fix/
cp "C:/Program Files/PostgreSQL/18/bin/libssl-3-x64.dll" build_fix/
```

---

### Task 1: Chat envelope and validation helpers

**Files:**
- Modify: `include/common.h` (constants near line 36; new struct after `HandshakeMessage`; new helpers near the other `serialize_*` functions)
- Create: `tests/test_chat_envelope.cpp`
- Modify: `CMakeLists.txt` (new test target)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `SecureComm::ChatType`, `SecureComm::ChatMessage`, `MAX_NAME_LEN`, `MAX_TEXT_LEN`, `serialize_chat(const ChatMessage&) -> std::vector<uint8_t>`, `deserialize_chat(const std::vector<uint8_t>&) -> ChatMessage`, `set_chat_field(char*, size_t, const std::string&)`, `get_chat_field(const char*, size_t) -> std::string`, `set_chat_text(ChatMessage&, const std::string&)`, `get_chat_text(const ChatMessage&) -> std::string`, `is_valid_name(const std::string&) -> bool`, `make_chat(ChatType) -> ChatMessage`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_chat_envelope.cpp`:

```cpp
// Regression test for the ChatMessage envelope carried inside the ciphertext.

#include "common.h"
#include <iostream>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

int main() {
    std::cout << "Envelope size" << std::endl;
    check(sizeof(ChatMessage) <= MAX_MESSAGE_SIZE - GCM_TAG_SIZE,
          "ChatMessage fits in one encrypted message");

    std::cout << "Round trip" << std::endl;
    ChatMessage msg = make_chat(ChatType::DIRECT);
    set_chat_field(msg.sender, MAX_NAME_LEN, "alice");
    set_chat_field(msg.recipient, MAX_NAME_LEN, "bob");
    set_chat_text(msg, "hello there");

    ChatMessage back = deserialize_chat(serialize_chat(msg));
    check(back.type == ChatType::DIRECT, "type survives round trip");
    check(get_chat_field(back.sender, MAX_NAME_LEN) == "alice", "sender survives round trip");
    check(get_chat_field(back.recipient, MAX_NAME_LEN) == "bob", "recipient survives round trip");
    check(get_chat_text(back) == "hello there", "text survives round trip");

    std::cout << "Text with embedded characters" << std::endl;
    ChatMessage punct = make_chat(ChatType::BROADCAST);
    set_chat_text(punct, "@bob is not a command here");
    check(get_chat_text(deserialize_chat(serialize_chat(punct))) == "@bob is not a command here",
          "text starting with @ is preserved verbatim");

    std::cout << "Oversized text is rejected, not truncated" << std::endl;
    ChatMessage bad = make_chat(ChatType::BROADCAST);
    bad.text_len = static_cast<uint16_t>(MAX_TEXT_LEN + 1);
    bool rejected = false;
    try {
        deserialize_chat(serialize_chat(bad));
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "text_len above MAX_TEXT_LEN throws");

    std::cout << "Short buffer is rejected" << std::endl;
    rejected = false;
    try {
        deserialize_chat(std::vector<uint8_t>(4, 0));
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "undersized buffer throws");

    std::cout << "Name validation" << std::endl;
    check(is_valid_name("alice"), "simple name accepted");
    check(is_valid_name("bob_2"), "underscore and digit accepted");
    check(!is_valid_name(""), "empty name rejected");
    check(!is_valid_name("has space"), "name with space rejected");
    check(!is_valid_name(std::string(MAX_NAME_LEN, 'x')), "name of MAX_NAME_LEN rejected");
    check(is_valid_name(std::string(MAX_NAME_LEN - 1, 'x')), "name of MAX_NAME_LEN-1 accepted");
    check(!is_valid_name("tab\there"), "name with tab rejected");

    std::cout << "Truncation safety" << std::endl;
    ChatMessage longname = make_chat(ChatType::DIRECT);
    set_chat_field(longname.recipient, MAX_NAME_LEN, std::string(100, 'z'));
    check(get_chat_field(longname.recipient, MAX_NAME_LEN).size() == MAX_NAME_LEN - 1,
          "over-long field is clamped and stays NUL-terminated");

    if (failures == 0) {
        std::cout << "All chat envelope tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " chat envelope test(s) failed" << std::endl;
    return 1;
}
```

- [ ] **Step 2: Add the test target**

In `CMakeLists.txt`, immediately after the `add_test(NAME aes_gcm COMMAND test_aes_gcm)` line:

```cmake
add_executable(test_chat_envelope
    tests/test_chat_envelope.cpp
)

target_include_directories(test_chat_envelope PRIVATE include crypto)
target_link_libraries(test_chat_envelope
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME chat_envelope COMMAND test_chat_envelope)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cmake --build build_fix --target test_chat_envelope`
Expected: FAIL to compile — `ChatType`, `ChatMessage`, `make_chat` are not declared.

- [ ] **Step 4: Add constants and the envelope struct**

In `include/common.h`, add to the constants block next to `MAX_PUBLIC_KEY_SIZE`:

```cpp
constexpr size_t MAX_NAME_LEN = 32;
constexpr size_t MAX_TEXT_LEN = 1024;
```

Add the enum next to the other enums, after `ForwardSecrecyType`:

```cpp
// Chat envelope types, carried inside the encrypted payload
enum class ChatType : uint8_t {
    REGISTER      = 0x01,
    REGISTER_OK   = 0x02,
    REGISTER_FAIL = 0x03,
    DIRECT        = 0x04,
    BROADCAST     = 0x05,
    WHO           = 0x06,
    ROSTER        = 0x07,
    PRESENCE      = 0x08,
    NOTICE        = 0x09,
};
```

Add the struct immediately after `HandshakeMessage`:

```cpp
// Chat message envelope. Travels inside the AES-GCM ciphertext, so the server
// can route on it while the network sees only ciphertext.
struct ChatMessage {
    ChatType type;
    char     sender[MAX_NAME_LEN];
    char     recipient[MAX_NAME_LEN];
    uint16_t text_len;
    char     text[MAX_TEXT_LEN];
};
```

- [ ] **Step 5: Add the helpers**

In `include/common.h`, after `deserialize_encrypted_message`:

```cpp
inline ChatMessage make_chat(ChatType type) {
    ChatMessage msg{};
    msg.type = type;
    msg.text_len = 0;
    return msg;
}

inline void set_chat_field(char* field, size_t field_size, const std::string& value) {
    std::memset(field, 0, field_size);
    const size_t copy_len = std::min(value.size(), field_size - 1);
    std::memcpy(field, value.data(), copy_len);
}

inline std::string get_chat_field(const char* field, size_t field_size) {
    size_t len = 0;
    while (len < field_size && field[len] != '\0') {
        ++len;
    }
    return std::string(field, len);
}

inline void set_chat_text(ChatMessage& msg, const std::string& text) {
    const size_t copy_len = std::min(text.size(), MAX_TEXT_LEN);
    std::memset(msg.text, 0, MAX_TEXT_LEN);
    std::memcpy(msg.text, text.data(), copy_len);
    msg.text_len = static_cast<uint16_t>(copy_len);
}

inline std::string get_chat_text(const ChatMessage& msg) {
    if (msg.text_len > MAX_TEXT_LEN) {
        throw std::runtime_error("Chat text_len out of range");
    }
    return std::string(msg.text, msg.text_len);
}

inline bool is_valid_name(const std::string& name) {
    if (name.empty() || name.size() >= MAX_NAME_LEN) {
        return false;
    }
    for (unsigned char c : name) {
        if (c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

inline std::vector<uint8_t> serialize_chat(const ChatMessage& msg) {
    std::vector<uint8_t> data(sizeof(ChatMessage));
    std::memcpy(data.data(), &msg, sizeof(ChatMessage));
    return data;
}

inline ChatMessage deserialize_chat(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(ChatMessage)) {
        throw std::runtime_error("Invalid chat message size");
    }
    ChatMessage msg;
    std::memcpy(&msg, data.data(), sizeof(ChatMessage));
    if (msg.text_len > MAX_TEXT_LEN) {
        throw std::runtime_error("Chat text_len out of range");
    }
    return msg;
}
```

`is_valid_name` uses the 0x21-0x7E range, which excludes space (0x20) and all control characters in one check.

- [ ] **Step 6: Run test to verify it passes**

Run: `cmake --build build_fix --target test_chat_envelope && ./build_fix/test_chat_envelope.exe`
Expected: PASS, "All chat envelope tests passed"

- [ ] **Step 7: Commit**

```bash
git add include/common.h tests/test_chat_envelope.cpp CMakeLists.txt
git commit -m "feat: add ChatMessage envelope and name validation

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Directional key derivation

**Files:**
- Modify: `crypto/crypto_utils.h` (add `SessionKeys`, declare `derive_directional_keys`)
- Modify: `crypto/crypto_utils.cpp` (implement it)
- Create: `tests/test_directional_keys.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: existing `CryptoManager::derive_shared_secret(dh_result, salt)` and `CryptoManager::rotate_session_key(current_key, session_id)`.
- Produces: `SecureComm::SessionKeys { std::vector<uint8_t> tx_key; std::vector<uint8_t> rx_key; }` and `CryptoManager::derive_directional_keys(const std::vector<uint8_t>& shared_secret, const std::vector<uint8_t>& nonce, bool is_server) -> SessionKeys`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_directional_keys.cpp`:

```cpp
// Regression test for directional session keys.
// Guards the rotation race: with one shared key, a message already in flight
// fails to decrypt when the peer rotates. Each direction must be rotated only
// by its own sender.

#include "crypto_utils.h"
#include <iostream>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

int main() {
    CryptoManager crypto;

    try {
        std::vector<uint8_t> shared_secret = crypto.generate_random_bytes(32);
        std::vector<uint8_t> nonce = crypto.generate_random_bytes(IV_SIZE);

        std::cout << "Mirrored derivation" << std::endl;
        SessionKeys server = crypto.derive_directional_keys(shared_secret, nonce, true);
        SessionKeys client = crypto.derive_directional_keys(shared_secret, nonce, false);

        check(server.tx_key.size() == KEY_SIZE, "tx key is KEY_SIZE bytes");
        check(server.rx_key.size() == KEY_SIZE, "rx key is KEY_SIZE bytes");
        check(server.tx_key == client.rx_key, "server tx matches client rx");
        check(server.rx_key == client.tx_key, "server rx matches client tx");
        check(server.tx_key != server.rx_key, "the two directions use different keys");

        std::cout << "Determinism" << std::endl;
        SessionKeys again = crypto.derive_directional_keys(shared_secret, nonce, true);
        check(again.tx_key == server.tx_key, "derivation is deterministic");

        std::cout << "Rotating one direction leaves the other alone" << std::endl;
        std::vector<uint8_t> session_id_bytes = {0x01, 0x02, 0x03, 0x04};

        std::vector<uint8_t> server_tx_before = server.tx_key;
        std::vector<uint8_t> server_rx_before = server.rx_key;

        // The server owns the server-to-client direction; the client rotates the
        // matching rx key when it reads the in-band marker.
        server.tx_key = crypto.rotate_session_key(server.tx_key, session_id_bytes);
        client.rx_key = crypto.rotate_session_key(client.rx_key, session_id_bytes);

        check(server.tx_key != server_tx_before, "rotation changes the key");
        check(server.tx_key == client.rx_key, "rotated direction still matches");
        check(server.rx_key == server_rx_before, "opposite direction is untouched");
        check(server.rx_key == client.tx_key, "opposite direction still matches");

        std::cout << "Rotating the other direction independently" << std::endl;
        client.tx_key = crypto.rotate_session_key(client.tx_key, session_id_bytes);
        server.rx_key = crypto.rotate_session_key(server.rx_key, session_id_bytes);

        check(server.rx_key == client.tx_key, "second direction matches after its own rotation");
        check(server.tx_key == client.rx_key, "first direction still matches");

        std::cout << "Different nonce gives different keys" << std::endl;
        std::vector<uint8_t> other_nonce = crypto.generate_random_bytes(IV_SIZE);
        SessionKeys other = crypto.derive_directional_keys(shared_secret, other_nonce, true);
        check(other.tx_key != server_tx_before, "nonce is mixed into derivation");

    } catch (const std::exception& e) {
        std::cout << "  FAIL: unexpected exception: " << e.what() << std::endl;
        ++failures;
    }

    if (failures == 0) {
        std::cout << "All directional key tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " directional key test(s) failed" << std::endl;
    return 1;
}
```

- [ ] **Step 2: Add the test target**

In `CMakeLists.txt`, after the `chat_envelope` test block:

```cmake
add_executable(test_directional_keys
    tests/test_directional_keys.cpp
)

target_include_directories(test_directional_keys PRIVATE include crypto)
target_link_libraries(test_directional_keys
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME directional_keys COMMAND test_directional_keys)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cmake --build build_fix --target test_directional_keys`
Expected: FAIL to compile — `SessionKeys` and `derive_directional_keys` are not declared.

- [ ] **Step 4: Declare the interface**

In `crypto/crypto_utils.h`, add before `class CryptoManager`:

```cpp
// A session's two keys. Each peer encrypts with tx_key and decrypts with rx_key;
// the roles are mirrored, so one peer's tx_key is the other's rx_key.
struct SessionKeys {
    std::vector<uint8_t> tx_key;
    std::vector<uint8_t> rx_key;
};
```

In the `CryptoManager` public section, directly under `derive_shared_secret`:

```cpp
    SessionKeys derive_directional_keys(const std::vector<uint8_t>& shared_secret,
                                       const std::vector<uint8_t>& nonce,
                                       bool is_server);
```

- [ ] **Step 5: Implement it**

In `crypto/crypto_utils.cpp`, after `derive_shared_secret`:

```cpp
SessionKeys CryptoManager::derive_directional_keys(const std::vector<uint8_t>& shared_secret,
                                                   const std::vector<uint8_t>& nonce,
                                                   bool is_server) {
    // Two distinct salts give two independent keys from one shared secret, so each
    // direction can be rotated by its own sender without disturbing the other.
    std::vector<uint8_t> c2s_salt = nonce;
    c2s_salt.push_back(0x01);
    std::vector<uint8_t> s2c_salt = nonce;
    s2c_salt.push_back(0x02);

    std::vector<uint8_t> client_to_server = derive_shared_secret(shared_secret, c2s_salt);
    std::vector<uint8_t> server_to_client = derive_shared_secret(shared_secret, s2c_salt);

    SessionKeys keys;
    if (is_server) {
        keys.tx_key = server_to_client;
        keys.rx_key = client_to_server;
    } else {
        keys.tx_key = client_to_server;
        keys.rx_key = server_to_client;
    }
    return keys;
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cmake --build build_fix --target test_directional_keys && ./build_fix/test_directional_keys.exe`
Expected: PASS, "All directional key tests passed"

- [ ] **Step 7: Commit**

```bash
git add crypto/crypto_utils.h crypto/crypto_utils.cpp tests/test_directional_keys.cpp CMakeLists.txt
git commit -m "feat: derive directional session keys

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire directional keys into the handshake

Echo behaviour must still work end to end after this task. Only the key material changes.

**Files:**
- Modify: `crypto/crypto_utils.h` (`SessionInfo`; `SessionManager` accessors)
- Modify: `crypto/crypto_utils.cpp` (`SessionManager` implementations)
- Modify: `server/server.cpp` (handshake key derivation; encrypt/decrypt call sites)
- Modify: `client/client.cpp` (handshake key derivation; encrypt/decrypt call sites)

**Interfaces:**
- Consumes: `CryptoManager::derive_directional_keys` from Task 2.
- Produces: `SessionInfo::tx_key`, `SessionInfo::rx_key`; `SessionManager::set_session_keys(uint32_t, const SessionKeys&)`, `SessionManager::get_tx_key(uint32_t)`, `SessionManager::get_rx_key(uint32_t)`, `SessionManager::rotate_tx_key(uint32_t)`, `SessionManager::rotate_rx_key(uint32_t)`.

- [ ] **Step 1: Replace the single key on SessionInfo**

In `include/common.h`, in `struct SessionInfo`, replace the `current_key` member with:

```cpp
    std::vector<uint8_t> tx_key;
    std::vector<uint8_t> rx_key;
```

- [ ] **Step 2: Replace the SessionManager key accessors**

In `crypto/crypto_utils.h`, in `class SessionManager`, replace the declarations of `set_session_key`, `get_session_key` and `rotate_session_key` with:

```cpp
    void set_session_keys(uint32_t session_id, const SessionKeys& keys);
    std::vector<uint8_t> get_tx_key(uint32_t session_id);
    std::vector<uint8_t> get_rx_key(uint32_t session_id);
    void rotate_tx_key(uint32_t session_id);
    void rotate_rx_key(uint32_t session_id);
```

In `crypto/crypto_utils.cpp`, replace the corresponding definitions with:

```cpp
static std::vector<uint8_t> session_id_to_bytes(uint32_t session_id) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&session_id),
                                reinterpret_cast<const uint8_t*>(&session_id) + sizeof(session_id));
}

void SessionManager::set_session_keys(uint32_t session_id, const SessionKeys& keys) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.tx_key = keys.tx_key;
        it->second.rx_key = keys.rx_key;
    }
}

std::vector<uint8_t> SessionManager::get_tx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Unknown session");
    }
    return it->second.tx_key;
}

std::vector<uint8_t> SessionManager::get_rx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Unknown session");
    }
    return it->second.rx_key;
}

void SessionManager::rotate_tx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.tx_key = crypto_manager_.rotate_session_key(it->second.tx_key,
                                                               session_id_to_bytes(session_id));
        it->second.key_rotated = true;
    }
}

void SessionManager::rotate_rx_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.rx_key = crypto_manager_.rotate_session_key(it->second.rx_key,
                                                               session_id_to_bytes(session_id));
    }
}
```

- [ ] **Step 3: Derive both keys in the server handshake**

In `server/server.cpp`, in `perform_handshake`, replace the block that derives and stores `session_key` with:

```cpp
            std::vector<uint8_t> client_nonce_vec(client_handshake.nonce, client_handshake.nonce + SecureComm::IV_SIZE);
            SecureComm::SessionKeys keys = crypto_manager_->derive_directional_keys(
                shared_secret, client_nonce_vec, true);

            session_manager_->set_session_keys(session.session_id, keys);
            session.shared_secret = shared_secret;
            session.tx_key = keys.tx_key;
            session.rx_key = keys.rx_key;
```

- [ ] **Step 4: Derive both keys in the client handshake**

In `client/client.cpp`, replace the member `std::vector<uint8_t> session_key_;` with:

```cpp
    SecureComm::SessionKeys session_keys_;
```

In `perform_handshake`, replace the line assigning `session_key_` with:

```cpp
            std::vector<uint8_t> server_nonce(server_handshake.nonce, server_handshake.nonce + SecureComm::IV_SIZE);
            session_keys_ = crypto_manager_->derive_directional_keys(shared_secret, server_nonce, false);
            current_session_.shared_secret = shared_secret;
            current_session_.tx_key = session_keys_.tx_key;
            current_session_.rx_key = session_keys_.rx_key;
```

- [ ] **Step 5: Point every encrypt at tx and every decrypt at rx**

In `client/client.cpp`: in `send_encrypted_message` use `session_keys_.tx_key` where `session_key_` was used; in `receive_encrypted_message` use `session_keys_.rx_key`.

In `server/server.cpp`: where the handler decrypts an inbound message use `session_manager_->get_rx_key(session.session_id)`; in `send_encrypted_message` use `session_manager_->get_tx_key(session.session_id)`.

Delete the counter-based rotation block in `client/client.cpp` (the `if (message_counter_ % 10 == 0)` block added previously) and the one in `server/server.cpp` (`if (message_counter % 10 == 0)`). Task 4 replaces both.

- [ ] **Step 6: Build and verify echo still works end to end**

```bash
cmake --build build_fix
cd build_fix && ./server.exe &
printf 'hello\nquit\n' | ./client.exe 127.0.0.1 8080
```

Expected: handshake completes and `Server response: Server received: hello` is printed, with empty stderr on both sides.

- [ ] **Step 7: Run the full suite**

Run: `cd build_fix && ctest --output-on-failure`
Expected: 4 tests pass — `dh_key_exchange`, `aes_gcm`, `chat_envelope`, `directional_keys`.

- [ ] **Step 8: Commit**

```bash
git add include/common.h crypto/crypto_utils.h crypto/crypto_utils.cpp server/server.cpp client/client.cpp
git commit -m "refactor: use directional keys for the session

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: In-band key rotation

**Files:**
- Modify: `server/server.cpp` (send rotation marker; handle inbound marker)
- Modify: `client/client.cpp` (send rotation marker; handle inbound marker)

**Interfaces:**
- Consumes: `SessionManager::rotate_tx_key`, `rotate_rx_key` from Task 3.
- Produces: on-wire behaviour — a header-only `MessageType::KEY_ROTATION` frame with `payload_size == 0` means "the sender has just rotated its tx key; rotate your rx key now".

- [ ] **Step 1: Send the marker from the server after every 10 sends**

In `server/server.cpp`, add a helper next to `send_encrypted_message`:

```cpp
    // Announces that this peer is rotating the direction it sends on. Header-only,
    // so it needs no key. Sent and applied under the same lock, so nothing can be
    // encrypted between the marker going out and the key changing.
    void rotate_tx_and_announce(const std::shared_ptr<ClientConnection>& conn) {
        SecureComm::MessageHeader header{};
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::KEY_ROTATION;
        header.sequence_number = 0;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = 0;
        header.flags = 0;

        if (!send_data(conn->socket, SecureComm::serialize_header(header))) {
            conn->alive = false;
            return;
        }
        session_manager_->rotate_tx_key(conn->session_id);
    }
```

Until Task 5 introduces `ClientConnection`, use the connection's socket and session id directly; the signature above is the final form and Task 5 supplies the type.

- [ ] **Step 2: Handle the inbound marker on the server**

In `server/server.cpp`, in the message loop, add a branch before the `ENCRYPTED_MESSAGE` branch:

```cpp
                if (header.type == SecureComm::MessageType::KEY_ROTATION) {
                    session_manager_->rotate_rx_key(session.session_id);
                    continue;
                }
```

Delete the old `KEY_ROTATION` branch that called `rotate_session_key` and `send_key_rotation_response`, and delete `send_key_rotation_response` itself. Rotation is no longer a request/response exchange.

- [ ] **Step 3: Mirror both halves on the client**

In `client/client.cpp`, add:

```cpp
    bool rotate_tx_and_announce() {
        SecureComm::MessageHeader header{};
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::KEY_ROTATION;
        header.sequence_number = message_counter_;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = 0;
        header.flags = 0;

        if (!send_data(SecureComm::serialize_header(header))) {
            return false;
        }
        std::lock_guard<std::mutex> lock(key_mutex_);
        session_keys_.tx_key = crypto_manager_->rotate_session_key(
            session_keys_.tx_key, session_id_bytes());
        return true;
    }

    std::vector<uint8_t> session_id_bytes() const {
        const uint32_t id = current_session_.session_id;
        return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&id),
                                    reinterpret_cast<const uint8_t*>(&id) + sizeof(id));
    }
```

Add `std::mutex key_mutex_;` as a member. Task 5 relies on it once a second thread exists.

In `send_encrypted_message`, after a successful send, replace the deleted counter block with:

```cpp
            if (message_counter_ % 10 == 0 && !rotate_tx_and_announce()) {
                std::cerr << "Failed to rotate key" << std::endl;
                return false;
            }
```

- [ ] **Step 4: Handle the inbound marker on the client**

Where the client reads a frame, branch on the header before decrypting:

```cpp
        if (header.type == SecureComm::MessageType::KEY_ROTATION) {
            std::lock_guard<std::mutex> lock(key_mutex_);
            session_keys_.rx_key = crypto_manager_->rotate_session_key(
                session_keys_.rx_key, session_id_bytes());
            return;
        }
```

- [ ] **Step 5: Call the server-side rotation after every 10 sends**

In `server/server.cpp`, in `send_encrypted_message`, increment a per-session send counter and call `rotate_tx_and_announce` when it reaches a multiple of 10.

- [ ] **Step 6: Verify rotation across the boundary**

```bash
cd build_fix && ./server.exe &
printf 'm1\nm2\nm3\nm4\nm5\nm6\nm7\nm8\nm9\nm10\nm11\nm12\nquit\n' | ./client.exe 127.0.0.1 8080
```

Expected: all 12 messages get a response; both stderr streams empty. Messages 11 and 12 crossing the rotation is the point of the test.

- [ ] **Step 7: Commit**

```bash
git add server/server.cpp client/client.cpp
git commit -m "fix: rotate keys in band, per direction

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Client receive thread

After this task the client prints server messages from a background thread. Echo still works; nothing routes yet.

**Files:**
- Modify: `client/client.cpp`

**Interfaces:**
- Consumes: `key_mutex_`, `session_keys_` from Tasks 3 and 4.
- Produces: `SecureClient::receive_loop()`, `SecureClient::dispatch_frame(const std::vector<uint8_t>&)`, `SecureClient::print_incoming(const std::string&)`, member `std::atomic<bool> connected_`.

- [ ] **Step 1: Add the members**

```cpp
    std::thread receive_thread_;
    std::atomic<bool> connected_{false};
```

Add `#include <thread>` and `#include <atomic>`.

- [ ] **Step 2: Add the loop and dispatcher**

```cpp
    void print_incoming(const std::string& line) {
        // Redraw the prompt so an arriving message does not corrupt a half-typed line.
        std::cout << "\r" << line << std::endl << "> " << std::flush;
    }

    void dispatch_frame(const std::vector<uint8_t>& data) {
        SecureComm::MessageHeader header = SecureComm::deserialize_header(data);

        if (header.type == SecureComm::MessageType::KEY_ROTATION) {
            std::lock_guard<std::mutex> lock(key_mutex_);
            session_keys_.rx_key = crypto_manager_->rotate_session_key(
                session_keys_.rx_key, session_id_bytes());
            return;
        }

        if (header.type != SecureComm::MessageType::ENCRYPTED_MESSAGE) {
            return;
        }

        std::vector<uint8_t> payload(data.begin() + sizeof(SecureComm::MessageHeader), data.end());
        SecureComm::EncryptedMessage msg = SecureComm::deserialize_encrypted_message(payload);

        std::vector<uint8_t> rx;
        {
            std::lock_guard<std::mutex> lock(key_mutex_);
            rx = session_keys_.rx_key;
        }

        std::vector<uint8_t> iv(msg.iv, msg.iv + SecureComm::IV_SIZE);
        std::vector<uint8_t> cipher(msg.encrypted_data, msg.encrypted_data + header.payload_size);
        std::vector<uint8_t> plain = crypto_manager_->decrypt_aes_gcm(cipher, rx, iv);

        handle_chat(SecureComm::deserialize_chat(plain));
    }

    void receive_loop() {
        while (connected_) {
            std::vector<uint8_t> data = receive_data();
            if (data.empty()) {
                if (connected_) {
                    connected_ = false;
                    print_incoming("*** disconnected from server ***");
                }
                break;
            }
            try {
                dispatch_frame(data);
            } catch (const std::exception& e) {
                connected_ = false;
                print_incoming(std::string("*** receive error: ") + e.what() + " ***");
                break;
            }
        }
    }
```

- [ ] **Step 3: Add a provisional chat handler**

Task 7 fills this in. For now it prints the text so echo still shows:

```cpp
    void handle_chat(const SecureComm::ChatMessage& msg) {
        print_incoming(SecureComm::get_chat_text(msg));
    }
```

- [ ] **Step 4: Start and stop the thread**

After the handshake succeeds:

```cpp
        connected_ = true;
        receive_thread_ = std::thread(&SecureClient::receive_loop, this);
```

On disconnect, before closing the socket:

```cpp
        connected_ = false;
#ifdef _WIN32
        shutdown(client_socket_, SD_BOTH);
#else
        shutdown(client_socket_, SHUT_RDWR);
#endif
        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }
```

`shutdown` unblocks the receive thread, which would otherwise sit in `recv` forever.

- [ ] **Step 5: Stop waiting for a reply inline**

In `send_encrypted_message`, delete the `receive_encrypted_message()` call and the `Server response:` print. Replies now arrive on the receive thread. Delete `receive_encrypted_message` if nothing else calls it.

Wrap the server echo in a `ChatMessage` of type `NOTICE` in `server/server.cpp` so the client can decode it, using `set_chat_text`.

- [ ] **Step 6: Verify**

```bash
cd build_fix && ./server.exe &
printf 'hello\nquit\n' | ./client.exe 127.0.0.1 8080
```

Expected: the echo still prints, now from the receive thread, and the client exits cleanly with status 0 rather than hanging.

- [ ] **Step 7: Commit**

```bash
git add client/client.cpp server/server.cpp
git commit -m "feat: receive server messages on a background thread

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Connection registry and name registration

**Files:**
- Modify: `server/server.cpp` (registry, `ClientConnection`, REGISTER handling)
- Modify: `client/client.cpp` (name prompt and retry loop)

**Interfaces:**
- Consumes: `is_valid_name`, `make_chat`, `set_chat_field`, `set_chat_text` from Task 1.
- Produces: `ClientConnection`; `SecureServer::register_name(const std::string&, const std::shared_ptr<ClientConnection>&) -> bool`, `unregister(const std::shared_ptr<ClientConnection>&)`, `lookup(const std::string&) -> std::shared_ptr<ClientConnection>`, `roster_snapshot() -> std::vector<std::shared_ptr<ClientConnection>>`, `send_chat(const std::shared_ptr<ClientConnection>&, const SecureComm::ChatMessage&)`.

- [ ] **Step 1: Define the connection type and registry**

In `server/server.cpp`, above `class SecureServer`:

```cpp
struct ClientConnection {
    int               socket = -1;
    uint32_t          session_id = 0;
    std::string       name;
    std::mutex        send_mutex;
    std::atomic<bool> alive{true};
};
```

Members on `SecureServer`:

```cpp
    std::map<std::string, std::shared_ptr<ClientConnection>> registry_;
    std::mutex registry_mutex_;
```

Add `#include <map>`, `#include <memory>`, `#include <atomic>`.

- [ ] **Step 2: Add the registry operations**

```cpp
    bool register_name(const std::string& name, const std::shared_ptr<ClientConnection>& conn) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        if (registry_.find(name) != registry_.end()) {
            return false;
        }
        registry_[name] = conn;
        conn->name = name;
        return true;
    }

    void unregister(const std::shared_ptr<ClientConnection>& conn) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        if (!conn->name.empty()) {
            registry_.erase(conn->name);
        }
    }

    std::shared_ptr<ClientConnection> lookup(const std::string& name) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        auto it = registry_.find(name);
        return it == registry_.end() ? nullptr : it->second;
    }

    // Returns a snapshot so callers can send without holding registry_mutex_.
    std::vector<std::shared_ptr<ClientConnection>> roster_snapshot() {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<std::shared_ptr<ClientConnection>> out;
        out.reserve(registry_.size());
        for (const auto& entry : registry_) {
            out.push_back(entry.second);
        }
        return out;
    }
```

- [ ] **Step 3: Add the locked send path**

```cpp
    void send_chat(const std::shared_ptr<ClientConnection>& conn, const SecureComm::ChatMessage& msg) {
        if (!conn->alive) {
            return;
        }
        // Encryption happens inside the lock so a rotation cannot land between
        // encrypting and sending, and so two relaying threads cannot interleave frames.
        std::lock_guard<std::mutex> lock(conn->send_mutex);
        try {
            std::vector<uint8_t> tx = session_manager_->get_tx_key(conn->session_id);
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            std::vector<uint8_t> cipher =
                crypto_manager_->encrypt_aes_gcm(SecureComm::serialize_chat(msg), tx, iv);

            SecureComm::EncryptedMessage out{};
            out.session_id = conn->session_id;
            out.message_id = 0;
            std::copy(iv.begin(), iv.end(), out.iv);
            if (cipher.size() > SecureComm::MAX_MESSAGE_SIZE) {
                return;
            }
            std::copy(cipher.begin(), cipher.end(), out.encrypted_data);

            SecureComm::MessageHeader header{};
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = 0;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(cipher.size());
            header.flags = 0;

            std::vector<uint8_t> frame = SecureComm::serialize_header(header);
            std::vector<uint8_t> body = SecureComm::serialize_encrypted_message(out);
            frame.insert(frame.end(), body.begin(), body.end());

            if (!send_data(conn->socket, frame)) {
                conn->alive = false;
            }
        } catch (const std::exception&) {
            conn->alive = false;
        }
    }

    void send_notice(const std::shared_ptr<ClientConnection>& conn, const std::string& text) {
        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::NOTICE);
        SecureComm::set_chat_text(msg, text);
        send_chat(conn, msg);
    }
```

- [ ] **Step 4: Handle REGISTER**

In the message loop, after decrypting into a `ChatMessage`:

```cpp
                if (chat.type == SecureComm::ChatType::REGISTER) {
                    const std::string wanted = SecureComm::get_chat_text(chat);
                    std::string reason;
                    if (!SecureComm::is_valid_name(wanted)) {
                        reason = "Name must be 1-31 printable characters with no spaces";
                    } else if (!register_name(wanted, conn)) {
                        reason = "That name is taken";
                    }

                    SecureComm::ChatMessage reply = SecureComm::make_chat(
                        reason.empty() ? SecureComm::ChatType::REGISTER_OK
                                       : SecureComm::ChatType::REGISTER_FAIL);
                    SecureComm::set_chat_text(reply, reason.empty() ? wanted : reason);
                    send_chat(conn, reply);
                    continue;
                }

                if (conn->name.empty()) {
                    send_notice(conn, "Register a name before sending messages");
                    continue;
                }
```

- [ ] **Step 5: Prompt for a name on the client**

In `client/client.cpp`, after the handshake and after starting the receive thread:

```cpp
    bool register_name() {
        std::string name;
        while (connected_) {
            std::cout << "Enter your name: " << std::flush;
            if (!std::getline(std::cin, name)) {
                return false;
            }

            SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::REGISTER);
            SecureComm::set_chat_text(msg, name);
            if (!send_chat(msg)) {
                return false;
            }

            std::unique_lock<std::mutex> lock(register_mutex_);
            register_cv_.wait(lock, [this] { return register_answered_ || !connected_; });
            if (!connected_) {
                return false;
            }
            register_answered_ = false;
            if (register_ok_) {
                my_name_ = name;
                return true;
            }
        }
        return false;
    }
```

Add members `std::mutex register_mutex_; std::condition_variable register_cv_; bool register_answered_ = false; bool register_ok_ = false; std::string my_name_;` and `#include <condition_variable>`.

In `handle_chat`, add:

```cpp
        if (msg.type == SecureComm::ChatType::REGISTER_OK ||
            msg.type == SecureComm::ChatType::REGISTER_FAIL) {
            {
                std::lock_guard<std::mutex> lock(register_mutex_);
                register_ok_ = (msg.type == SecureComm::ChatType::REGISTER_OK);
                register_answered_ = true;
            }
            if (msg.type == SecureComm::ChatType::REGISTER_FAIL) {
                std::cout << SecureComm::get_chat_text(msg) << std::endl;
            } else {
                std::cout << "Registered as " << SecureComm::get_chat_text(msg) << std::endl;
            }
            register_cv_.notify_one();
            return;
        }
```

Add `send_chat(const SecureComm::ChatMessage&)` on the client, mirroring the server's but using `session_keys_.tx_key` under `key_mutex_`, and replace the body of `send_encrypted_message` with a call to it.

- [ ] **Step 6: Unregister on disconnect**

Where the client handler exits, before closing the socket:

```cpp
        conn->alive = false;
        unregister(conn);
```

- [ ] **Step 7: Verify registration and clash**

```bash
cd build_fix && ./server.exe &
printf 'alice\nquit\n' | ./client.exe 127.0.0.1 8080 &
sleep 2
printf 'alice\nbob\nquit\n' | ./client.exe 127.0.0.1 8080
```

Expected: the first client registers as `alice`; the second is told the name is taken, then registers as `bob`.

- [ ] **Step 8: Commit**

```bash
git add server/server.cpp client/client.cpp
git commit -m "feat: register client names against a server registry

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Direct and broadcast routing

**Files:**
- Modify: `server/server.cpp` (routing)
- Modify: `client/client.cpp` (input parsing, display)

**Interfaces:**
- Consumes: `lookup`, `roster_snapshot`, `send_chat`, `send_notice` from Task 6.
- Produces: `SecureServer::route_direct(...)`, `SecureServer::route_broadcast(...)`; client input parsing for `@name` and plain text.

- [ ] **Step 1: Route on the server**

```cpp
                if (chat.type == SecureComm::ChatType::DIRECT) {
                    const std::string to = SecureComm::get_chat_field(chat.recipient, SecureComm::MAX_NAME_LEN);
                    std::shared_ptr<ClientConnection> target = lookup(to);
                    if (!target) {
                        send_notice(conn, "No such user: " + to);
                        continue;
                    }
                    SecureComm::ChatMessage out = SecureComm::make_chat(SecureComm::ChatType::DIRECT);
                    SecureComm::set_chat_field(out.sender, SecureComm::MAX_NAME_LEN, conn->name);
                    SecureComm::set_chat_field(out.recipient, SecureComm::MAX_NAME_LEN, to);
                    SecureComm::set_chat_text(out, SecureComm::get_chat_text(chat));
                    send_chat(target, out);
                    continue;
                }

                if (chat.type == SecureComm::ChatType::BROADCAST) {
                    SecureComm::ChatMessage out = SecureComm::make_chat(SecureComm::ChatType::BROADCAST);
                    SecureComm::set_chat_field(out.sender, SecureComm::MAX_NAME_LEN, conn->name);
                    SecureComm::set_chat_text(out, SecureComm::get_chat_text(chat));
                    for (const auto& peer : roster_snapshot()) {
                        if (peer->name != conn->name) {
                            send_chat(peer, out);
                        }
                    }
                    continue;
                }
```

The `sender` field is set here from `conn->name`, never from `chat.sender`. That is what stops a client forging identity.

Delete the old echo branch that replied `"Server received: ..."`.

- [ ] **Step 2: Parse input on the client**

```cpp
    void send_line(const std::string& line) {
        if (line.rfind("@", 0) == 0) {
            const size_t space = line.find(' ');
            if (space == std::string::npos) {
                std::cout << "Usage: @name message" << std::endl;
                return;
            }
            const std::string to = line.substr(1, space - 1);
            SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::DIRECT);
            SecureComm::set_chat_field(msg.recipient, SecureComm::MAX_NAME_LEN, to);
            SecureComm::set_chat_text(msg, line.substr(space + 1));
            send_chat(msg);
            return;
        }

        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::BROADCAST);
        SecureComm::set_chat_text(msg, line);
        send_chat(msg);
    }
```

- [ ] **Step 3: Display incoming messages**

In `handle_chat`:

```cpp
        const std::string from = SecureComm::get_chat_field(msg.sender, SecureComm::MAX_NAME_LEN);
        switch (msg.type) {
            case SecureComm::ChatType::DIRECT:
                print_incoming("[" + from + " -> you] " + SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::BROADCAST:
                print_incoming("[" + from + "] " + SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::NOTICE:
                print_incoming("*** " + SecureComm::get_chat_text(msg) + " ***");
                break;
            default:
                break;
        }
```

- [ ] **Step 4: Verify**

```bash
cd build_fix && ./server.exe &
printf 'alice\n' > /tmp/a.in; printf 'sleep\n' >> /tmp/a.in
./client.exe 127.0.0.1 8080 < /tmp/a.in &
sleep 3
printf 'bob\n@alice private hello\nhello everyone\nquit\n' | ./client.exe 127.0.0.1 8080
```

Expected: alice's output shows `[bob -> you] private hello` and `[bob] hello everyone`; bob sees neither of his own messages echoed.

- [ ] **Step 5: Commit**

```bash
git add server/server.cpp client/client.cpp
git commit -m "feat: route direct and broadcast messages by name

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Roster and presence

**Files:**
- Modify: `server/server.cpp`
- Modify: `client/client.cpp`

**Interfaces:**
- Consumes: `roster_snapshot`, `send_chat` from Task 6.
- Produces: `SecureServer::broadcast_presence(const std::string& name, bool joined, const std::string& except)`.

- [ ] **Step 1: Handle WHO**

```cpp
                if (chat.type == SecureComm::ChatType::WHO) {
                    std::string names;
                    size_t count = 0;
                    for (const auto& peer : roster_snapshot()) {
                        if (!names.empty()) {
                            names += ", ";
                        }
                        names += peer->name;
                        ++count;
                    }
                    SecureComm::ChatMessage reply = SecureComm::make_chat(SecureComm::ChatType::ROSTER);
                    SecureComm::set_chat_text(reply, "Online (" + std::to_string(count) + "): " + names);
                    send_chat(conn, reply);
                    continue;
                }
```

- [ ] **Step 2: Broadcast presence**

```cpp
    void broadcast_presence(const std::string& name, bool joined, const std::string& except) {
        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::PRESENCE);
        SecureComm::set_chat_field(msg.sender, SecureComm::MAX_NAME_LEN, name);
        SecureComm::set_chat_text(msg, name + (joined ? " joined" : " left"));
        for (const auto& peer : roster_snapshot()) {
            if (peer->name != except) {
                send_chat(peer, msg);
            }
        }
    }
```

Call it with `joined = true` right after a successful `register_name`, passing the new name as `except`. Call it with `joined = false` after `unregister` on disconnect, passing an empty `except`.

- [ ] **Step 3: Client sends WHO and prints presence**

In `send_line`, before the `@` branch:

```cpp
        if (line == "/who") {
            send_chat(SecureComm::make_chat(SecureComm::ChatType::WHO));
            return;
        }
```

In the `handle_chat` switch:

```cpp
            case SecureComm::ChatType::ROSTER:
                print_incoming(SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::PRESENCE:
                print_incoming("*** " + SecureComm::get_chat_text(msg) + " ***");
                break;
```

- [ ] **Step 4: Verify**

Connect two clients; the second joining should print `*** bob joined ***` on the first. `/who` should list both. Quitting one should print `*** bob left ***` on the other.

- [ ] **Step 5: Commit**

```bash
git add server/server.cpp client/client.cpp
git commit -m "feat: add roster command and presence notices

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Integration test and documentation

**Files:**
- Create: `tests/integration_chat.sh`
- Modify: `CMakeLists.txt`
- Modify: `README.md`

**Interfaces:**
- Consumes: the finished `server.exe` and `client.exe`.
- Produces: ctest case `chat_integration`.

- [ ] **Step 1: Write the integration script**

Create `tests/integration_chat.sh`. It takes the build directory as `$1`:

```bash
#!/usr/bin/env bash
# Three-client integration test for relayed chat.
set -u

BUILD="${1:-build_fix}"
cd "$BUILD" || exit 1
WORK=$(mktemp -d)
fail=0

check() {
    if [ "$1" -eq 0 ]; then
        echo "  PASS: $2"
    else
        echo "  FAIL: $2"
        fail=$((fail + 1))
    fi
}

./server.exe > "$WORK/server.log" 2>&1 &
SRV=$!
sleep 3

# alice stays connected long enough to receive from the others
{ echo alice; sleep 12; echo quit; } | ./client.exe 127.0.0.1 8080 > "$WORK/alice.out" 2>&1 &
sleep 3

# bob tries alice's name first, which must be refused, then registers
{ echo alice; sleep 1; echo bob; sleep 1; echo "@alice direct-to-alice";
  sleep 1; echo "broadcast-from-bob"; sleep 1; echo /who;
  for i in $(seq 1 12); do echo "filler-$i"; sleep 0.2; done
  sleep 1; echo "after-rotation"; sleep 1; echo quit; } \
  | ./client.exe 127.0.0.1 8080 > "$WORK/bob.out" 2>&1 &
sleep 3

{ echo carol; sleep 6; echo quit; } | ./client.exe 127.0.0.1 8080 > "$WORK/carol.out" 2>&1 &
wait
kill $SRV 2>/dev/null

grep -q "taken" "$WORK/bob.out"; check $? "duplicate name refused"
grep -q "Registered as bob" "$WORK/bob.out"; check $? "retry with a free name succeeds"
grep -q "direct-to-alice" "$WORK/alice.out"; check $? "direct message reaches its recipient"
grep -q "direct-to-alice" "$WORK/carol.out"; [ $? -ne 0 ]; check $? "direct message does not reach anyone else"
grep -q "broadcast-from-bob" "$WORK/alice.out"; check $? "broadcast reaches alice"
grep -q "broadcast-from-bob" "$WORK/carol.out"; check $? "broadcast reaches carol"
grep -q "broadcast-from-bob" "$WORK/bob.out"; [ $? -ne 0 ]; check $? "broadcast does not echo to sender"
grep -q "Online" "$WORK/bob.out"; check $? "/who returns a roster"
grep -q "carol joined" "$WORK/alice.out"; check $? "join notice delivered"
grep -q "after-rotation" "$WORK/alice.out"; check $? "traffic survives a key rotation with relays in flight"
grep -qi "error\|failed" "$WORK/server.log"; [ $? -ne 0 ]; check $? "server log is clean"

rm -rf "$WORK"
[ "$fail" -eq 0 ] && echo "All chat integration tests passed" && exit 0
echo "$fail integration test(s) failed"
exit 1
```

- [ ] **Step 2: Register it with ctest**

```cmake
find_program(BASH_PROGRAM bash)
if(BASH_PROGRAM)
    add_test(NAME chat_integration
             COMMAND ${BASH_PROGRAM} ${CMAKE_SOURCE_DIR}/tests/integration_chat.sh $<TARGET_FILE_DIR:server>)
endif()
```

- [ ] **Step 3: Run it**

Run: `cd build_fix && ctest --output-on-failure`
Expected: 5 tests pass — `dh_key_exchange`, `aes_gcm`, `chat_envelope`, `directional_keys`, `chat_integration`.

- [ ] **Step 4: Document the chat commands**

Replace the "Interactive Client Commands" section of `README.md` with the name prompt, the `@name` / `/who` / `quit` table, the name rules, and a note that the server can read all relayed traffic.

- [ ] **Step 5: Commit**

```bash
git add tests/integration_chat.sh CMakeLists.txt README.md
git commit -m "test: add three-client chat integration test

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes

**Spec coverage.** Envelope and constants, Task 1. Name rules and validation, Task 1. Registration flow with re-prompt, Task 6. Directional keys, Tasks 2 and 3. In-band rotation, Task 4. Registry and the two concurrency rules, Task 6. Routing, Task 7. Roster and presence, Task 8. Client receive thread and prompt redraw, Task 5. Error handling appears in the task that owns each path: oversized `text_len` in Task 1, unregistered senders and unknown recipients in Tasks 6 and 7, dead sockets in Task 6's `send_chat`. Testing, Tasks 1, 2 and 9. README, Task 9.

**Naming consistency.** `set_chat_field`/`get_chat_field` are used with an explicit `MAX_NAME_LEN` argument everywhere. `send_chat` is the single send path on both sides. `rotate_tx_and_announce` is the name in both server and client.

**Known ordering note.** Task 4 references `ClientConnection`, which Task 6 defines. If tasks run strictly in order, implement Task 4's server-side rotation against the socket and session id directly, then adjust the signature in Task 6. This is called out inline in Task 4, Step 1.
