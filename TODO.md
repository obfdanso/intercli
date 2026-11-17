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
  the room code (worse on IPv6, where changing address is easy). Banning the person's
  key as well would help; until then, change the room code after a ban.
- Someone on the host's own PC is only banned by name.

## Offline delivery and receipts
- Names aren't accounts: a message kept for someone who is away is handed to whoever
  next joins under that name from the same address (from another address it is thrown
  away, so a changed address loses the messages). It is sealed for the first person's
  key, so someone else can't read it, but the server could check the key before handing
  it over at all.
- Kept messages live in the server's memory: they are lost when the chat ends, capped at
  50 per person (10 from any one sender), and dropped after 24 hours.
- Kept messages arrive without their original time.
- Read receipts can't be switched off, and exist only for direct messages.

## Server
- One event loop serves every connection. The key exchange for a new connection runs in
  that loop, so many people joining at the same moment wait on each other.
- Never measured with many clients (tests use a handful).
- While one client has a lot of output waiting, the server stops reading from everyone
  until it drains. A client that takes it too slowly is dropped after about five seconds,
  but could reconnect and do it again; flow control per sender would be better.
- A client on a very slow link (under about 50 KB/s) is dropped while receiving a big file.

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
- The host can read messages to everyone and to rooms (only direct messages and direct
  files are end-to-end encrypted).

## End-to-end encryption
- Rooms and messages to everyone are not sealed. Rooms would need a key shared by the
  members and changed when someone leaves.
- No forward secrecy: the key two people share never changes, so a stolen key file opens
  recorded old messages. Needs a ratchet (new keys as the conversation goes on).
- A changed key is accepted by sending again after the warning; there is no "verified"
  mark for a person whose safety code was compared, and no way to refuse the new key
  for good.
- The terminal client's key file is not encrypted on disk (the app's is, by Windows).
- The server still sees who writes to whom, when, and how much.
- One key per PC account: the same person on two PCs has two keys, and each switch
  looks like a key change to others.
- Read receipts, and the names in a file transfer's first notice, are not sealed.

## Still to build
- X25519 + HKDF key exchange for the connection to the server, with explicit
  serialisation (skipped for now; direct messages already use X25519 + HKDF).
- Packaging and CI: installer, GitHub Actions builds, fuzzing of the frame parser.

## Never checked on screen
These compile and their logic is tested, but nobody has clicked through them yet:
host buttons (Remove, Ban, New Code), the room box and Leave Room, drag-and-drop sending,
picture previews, click on a file, the receipt line under a conversation, the safety
code for private messages in the details panel, and the key-change warning.
