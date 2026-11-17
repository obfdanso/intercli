# To do later

Known limits, written down so they aren't forgotten. Each is something that works today
but should be better.

## File transfer
- No attach button in the desktop app: drag and drop is the only way to send a file.
- No progress bar and no cancel. A file shows as sent at once; a failure is reported after.
- After restarting the app, a saved file message is text only (no preview, no click).
- Slow for big files: an 8 MB file is about 8,000 messages with a key rotation every ten.
  Only tested with files of a few tens of KB.
- The terminal client doesn't mark received files as downloaded (the app does, on Windows).

## Rooms
- No member list for a room.
- Rooms have no code or owner: anyone in the chat can list and join them.

## Host controls
- Only in the desktop app; `server.exe` can't kick, ban or change the room code.
- Bans last until the chat ends and aren't kept between sessions.
- A ban is by name and exact address. Someone who changes both can rejoin if they know
  the room code (worse on IPv6, where changing address is easy). Needs per-user identity
  keys; until then, change the room code after a ban.
- Someone on the host's own PC is only banned by name.

## Offline delivery and receipts
- Names aren't accounts: a message kept for someone who is away goes to whoever next
  joins under that name from the same address (from another address it is thrown away,
  so a changed address loses the messages). Needs per-user identity keys.
- Kept messages live in the server's memory: they are lost when the chat ends, capped at
  50 per person (10 from any one sender), and dropped after 24 hours.
- Kept messages arrive without their original time.
- Read receipts can't be switched off, and exist only for direct messages.

## Server
- One event loop serves every connection. The key exchange for a new connection runs in
  that loop, so many people joining at the same moment wait on each other.
- Never measured with many clients (tests use a handful).

## Network
- Room code lockouts count a whole IPv6 network (/64) as one address, so one machine can
  use up its neighbours' guesses over IPv6. IPv4 is unaffected.
- "Chats nearby" discovery is IPv4 only; the host's address in the details panel lists
  IPv4 addresses only.
- If the discovery port can't be used, hosting works but the chat silently doesn't show
  under "Chats nearby".
- A hosted chat in the desktop app has no switch for IPv6 beyond the local network.
- Someone who connects but never picks a name can stay connected indefinitely.

## Chat
- The "who is online" reply holds about 30 long names; more only appear as they join.
- The host can read every message (no end-to-end encryption yet).

## Still to build
- X25519 + HKDF key exchange with explicit serialisation (skipped for now).
- End-to-end encryption with per-user identity keys.
- Packaging and CI: installer, GitHub Actions builds, fuzzing of the frame parser.

## Never checked on screen
These compile and their logic is tested, but nobody has clicked through them yet:
host buttons (Remove, Ban, New Code), the room box and Leave Room, drag-and-drop sending,
picture previews, click on a file, and the receipt line under a conversation.
