# Server-Relayed Chat with Name Registration — Design

Date: 2026-09-10
Status: Approved for implementation planning

## Overview

SecureComm today is a request/response echo protocol: each client establishes an
encrypted session with the server, sends a message, and receives `"Server received: ..."`
back. Clients cannot see or address one another.

This design adds client-to-client chat relayed through the server, addressed by
human-chosen names rather than numeric IDs. It also replaces the message-counter key
rotation scheme, which cannot survive the server pushing unsolicited messages.

## Goals

- A client registers a name when its session starts, and is addressed by that name.
- Direct messages to one named recipient.
- Broadcast messages to everyone connected.
- A roster command and join/leave notices so names are discoverable.
- Key rotation that remains correct when relayed messages are in flight.

## Non-goals

- End-to-end encryption between clients. The server decrypts and re-encrypts every
  relayed message, so it can read all traffic. This is a deliberate first step; the
  structured envelope chosen here is a prerequisite for adding true client-to-client
  encryption later without redesigning the wire format.
- Offline delivery, message history, or persistence. Messages to a disconnected name
  are rejected, not queued.
- Authentication of names. Anyone may claim any unused name.

## Trust model

The server is trusted with plaintext. Confidentiality holds against a network observer,
not against the server operator. Routing metadata (who is talking to whom) travels
inside the ciphertext and is therefore also hidden from the network, though not from
the server.

Clients cannot forge identity: the `sender` field is stamped by the server from its
registry at delivery time and is ignored on inbound messages.

## Protocol

The outer `EncryptedMessage`, the 4-byte length framing, and the AES-256-GCM layer are
unchanged. The change is entirely in what the plaintext contains.

### Envelope

```cpp
constexpr size_t MAX_NAME_LEN = 32;
constexpr size_t MAX_TEXT_LEN = 1024;

enum class ChatType : uint8_t {
    REGISTER      = 0x01,  // client -> server: claim a name
    REGISTER_OK   = 0x02,  // server -> client: accepted
    REGISTER_FAIL = 0x03,  // server -> client: rejected, reason in text
    DIRECT        = 0x04,  // both ways: one named recipient
    BROADCAST     = 0x05,  // both ways: everyone else
    WHO           = 0x06,  // client -> server: roster request
    ROSTER        = 0x07,  // server -> client: roster in text
    PRESENCE      = 0x08,  // server -> client: joined / left
    NOTICE        = 0x09,  // server -> client: error or informational
};

struct ChatMessage {
    ChatType type;
    char     sender[MAX_NAME_LEN];     // server-stamped on delivery; ignored inbound
    char     recipient[MAX_NAME_LEN];  // client-filled for DIRECT
    uint16_t text_len;
    char     text[MAX_TEXT_LEN];
};
```

Size is 1091 bytes, 1107 once encrypted with the GCM tag, well inside the existing
`MAX_MESSAGE_SIZE` of 4096. No framing or buffer changes are required.

Name fields are NUL-padded. `text_len` gives the used length of `text`; an envelope
whose `text_len` exceeds `MAX_TEXT_LEN` is rejected rather than truncated.

### Name rules

1 to 31 characters, printable ASCII, no whitespace. The no-whitespace rule keeps names
typeable in the `@name` shorthand.

### Registration flow

The cryptographic handshake is unchanged and runs first. Immediately after it:

1. Client prompts locally: `Enter your name:`
2. Client sends `REGISTER` with the name in `text`.
3. Server validates the name, then checks the registry.
4. Server replies `REGISTER_OK`, or `REGISTER_FAIL` with a reason.
5. On failure the client re-prompts and retries; there is no retry limit.
6. On success the server broadcasts `PRESENCE` ("alice joined") to all other clients.

Until registration succeeds the server routes nothing from that client and answers any
other message type with a `NOTICE`.

### Client input conventions

Input parsing is a client-side convenience that populates the structured fields. The
protocol itself is unambiguous.

| Input | Sent as |
|---|---|
| `@bob hello` | `DIRECT`, recipient `bob` |
| `/who` | `WHO` |
| `quit` | disconnect |
| anything else | `BROADCAST` |

Accepted limitation: a broadcast whose text begins with `@` cannot be expressed. This
is a property of the shorthand, not of the protocol.

## Directional keys and rotation

### Problem

A single shared session key cannot be rotated safely once the server sends unsolicited
messages. If the server rotates and a client message encrypted with the old key is
already in flight, that message fails to decrypt. Announcing rotation in-band fixes only
the direction carrying the announcement.

The previous scheme — both sides counting messages and rotating at every tenth — is
strictly worse: a relayed message can arrive between a client's tenth message and its
rotation point, encrypted with a key the client has already discarded.

### Design

Each session derives two keys from the same shared secret using distinct salts:

- `tx_key` — used to encrypt what this peer sends.
- `rx_key` — used to decrypt what this peer receives.

The roles are mirrored, so the client's `tx_key` equals the server's `rx_key` and vice
versa.

A direction is rotated only by its own sender, announced in-band on that same stream:

1. Sender sends a `KEY_ROTATION` control frame (header-only, no encrypted body, so it
   needs no key).
2. Sender rotates its `tx_key`.
3. Receiver, reading frames in order, rotates its `rx_key` on encountering the frame.

Because a key only changes at a defined point in the stream it governs, and TCP
preserves order within a stream, both peers switch at the same byte. The opposite
direction is untouched.

Each peer rotates only its own `tx_key`, on its own schedule: after every 10 messages it
has sent on that session. The server therefore rotates the server-to-client direction and
the client rotates the client-to-server direction, each announcing it on the stream it
governs. Neither peer ever rotates a key it does not own, and the two directions rotate
at unrelated times.

On the server, rotating `tx_key` happens inside that connection's send mutex, holding the
mutex across both the frame send and the key change, so no relayed message can be
encrypted between the two.

## Server design

### Connection registry

```cpp
struct ClientConnection {
    int               socket;
    uint32_t          session_id;
    std::string       name;
    std::mutex        send_mutex;
    std::atomic<bool> alive;
};
```

Held as `std::map<std::string, std::shared_ptr<ClientConnection>>` guarded by
`registry_mutex_`.

`shared_ptr` is required: a relaying thread may be mid-send to a client that is
disconnecting. The connection object outlives the map entry until the last reference
drops, and `alive` makes late sends no-ops rather than writes to a closed socket.

### Concurrency rules

These two rules are the correctness core of the server change.

1. **Never hold `registry_mutex_` during socket I/O.** Look up the entry, copy the
   `shared_ptr`, release the lock, then send. Holding it across a write lets one slow
   or unresponsive client stall every other client.
2. **Every send takes that connection's `send_mutex`, and encryption happens inside
   it.** Previously each socket was written only by its own handler thread. Now bob's
   socket is written by bob's handler and by every other client's relay thread. Without
   serialization their frames interleave mid-frame and corrupt the stream. Encrypting
   inside the lock also prevents a rotation landing between encryption and send.

Broadcast copies the roster under the lock, releases it, then sends to each connection.

### Routing

| Type | Behaviour |
|---|---|
| `REGISTER` | Validate, check uniqueness, reply, broadcast `PRESENCE` on success |
| `DIRECT` | Look up recipient; deliver with `sender` stamped, or `NOTICE` if absent |
| `BROADCAST` | Deliver to all registered clients except the sender |

A client addressing its own name is not a special case: the registry lookup succeeds and
the message is delivered back to it. Broadcast, by contrast, always excludes the sender.
| `WHO` | Build roster string, reply `ROSTER` to requester only |

On disconnect the handler removes the registry entry, clears `alive`, and broadcasts
`PRESENCE` ("alice left").

## Client design

The main thread reads stdin, parses input, and sends. A new receive thread loops on
`receive_data()`, decrypts, and dispatches by `ChatType`, printing messages and handling
`KEY_ROTATION`.

Sending remains single-threaded, so no send mutex is needed client-side. The key pair is
shared — `rx_key` written by the receive thread, `tx_key` read by the main thread — and
goes behind a mutex. Reading and writing one socket from two threads in opposite
directions is safe.

Incoming messages may arrive mid-typing. The client prints incoming lines preceded by a
newline and reprints the `> ` prompt. This is conventional terminal-chat behaviour and
avoids introducing a TUI layer.

Termination: on socket close the receive thread prints a disconnect notice and exits so
the main thread is not left blocked.

## Error handling

Failures are reported to the sender rather than dropped silently.

| Condition | Response |
|---|---|
| `DIRECT` to an unknown or disconnected name | `NOTICE` to sender |
| Any chat message before registration | `NOTICE`, not routed |
| Name empty, over 31 chars, whitespace, or non-printable | `REGISTER_FAIL` with reason |
| Name already registered | `REGISTER_FAIL` with reason |
| `text_len` greater than `MAX_TEXT_LEN` | Reject envelope, `NOTICE`; never truncate |
| Send to a closed socket | Clear `alive`, drop send, reap entry |
| Decrypt failure | Log and close that connection |

Closing on decrypt failure is a deliberate change from current behaviour, which logs the
error and continues with a desynchronized key, producing garbage indefinitely.

## Testing

### Unit tests (ctest)

- **`chat_envelope`** — `ChatMessage` round-trips through serialization; oversized
  `text_len` is rejected rather than truncated; NUL-padded names compare correctly.
- **`directional_keys`** — client `tx_key` equals server `rx_key` and vice versa; after
  rotating one direction the pair still matches and the opposite direction is unchanged.

The existing `dh_key_exchange` and `aes_gcm` tests are unchanged.

### Integration test

A scripted test driving three real clients through pipes, asserting:

- A duplicate name is rejected and the retry succeeds.
- A direct message reaches only its recipient.
- A broadcast reaches every other client and not the sender.
- `/who` lists all connected names.
- Join and leave notices fire.
- Traffic continues to decrypt correctly across a key rotation while relayed messages
  are in flight.

The last assertion is the regression guard for the rotation race. The original defects
in this codebase survived because verification was manual, so this runs under `ctest`.

## Files affected

| File | Change |
|---|---|
| `include/common.h` | `ChatType`, `ChatMessage`, name/text constants, serialization helpers |
| `crypto/crypto_utils.{h,cpp}` | Directional key derivation; `SessionInfo` holds a key pair |
| `server/server.cpp` | Connection registry, routing, per-connection send mutex, presence |
| `client/client.cpp` | Name registration prompt, receive thread, input parsing, key pair |
| `CMakeLists.txt` | New test targets |
| `tests/` | `test_chat_envelope.cpp`, `test_directional_keys.cpp`, integration script |
| `README.md` | Chat usage, commands, name rules |

## Future work

- End-to-end encryption between clients, with the server relaying opaque ciphertext.
  The structured envelope in this design is the prerequisite.
- Offline message queueing.
- Name authentication.
- Porting `client/gui_client_win.cpp`, which targets a protocol API that no longer
  exists and is currently excluded from the build.
