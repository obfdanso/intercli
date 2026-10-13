#!/usr/bin/env bash
# Three-client integration test for relayed chat.
#
# Note on greps: the client prints incoming lines with a leading carriage return
# so an arriving message does not corrupt half-typed input. Patterns are
# therefore unanchored - "^\[" would never match.

set -u

BUILD="${1:-build_fix}"
cd "$BUILD" || { echo "cannot enter build dir $BUILD"; exit 1; }

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

check_absent() {
    if [ "$1" -ne 0 ]; then
        echo "  PASS: $2"
    else
        echo "  FAIL: $2"
        fail=$((fail + 1))
    fi
}

cleanup() {
    taskkill //F //IM server.exe >/dev/null 2>&1 || true
    pkill -f "server.exe" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Start fresh: a server left over from an earlier run would hold port 8080.
taskkill //F //IM server.exe >/dev/null 2>&1 || true
sleep 1

./server.exe > "$WORK/server.log" 2>&1 &
sleep 3

# alice stays connected long enough to receive everything the others send.
{ echo alice; sleep 30; echo quit; } | ./client.exe 127.0.0.1 8080 > "$WORK/alice.out" 2>&1 &
ALICE=$!
sleep 2

# carol joins after alice, so alice sees a join notice for her.
{ echo carol; sleep 26; echo quit; } | ./client.exe 127.0.0.1 8080 > "$WORK/carol.out" 2>&1 &
CAROL=$!
sleep 2

# bob claims a taken name first, then drives the traffic.
{ echo alice; sleep 1
  echo bob; sleep 1
  echo "@alice direct-to-alice"; sleep 1
  echo "broadcast-from-bob"; sleep 1
  echo /who; sleep 1
  echo "@ghost vanish"; sleep 1
  for i in $(seq 1 12); do echo "filler-$i"; sleep 0.3; done
  sleep 1
  echo "after-rotation"; sleep 2
  echo quit; } | ./client.exe 127.0.0.1 8080 > "$WORK/bob.out" 2>&1

# Wait only on the clients; the server runs until cleanup kills it.
wait $ALICE $CAROL

# dave's input ends without "quit"; the client must exit rather than spin.
{ echo dave; sleep 1; } | timeout 20 ./client.exe 127.0.0.1 8080 > "$WORK/dave.out" 2>&1
DAVE_STATUS=$?

echo "Registration"
grep -q "taken" "$WORK/bob.out"; check $? "duplicate name refused"
grep -q "Registered as bob" "$WORK/bob.out"; check $? "retry with a free name succeeds"

echo "Direct messages"
grep -q "direct-to-alice" "$WORK/alice.out"; check $? "direct message reaches its recipient"
grep -q "direct-to-alice" "$WORK/carol.out"; check_absent $? "direct message does not reach anyone else"
grep -q "No such user: ghost" "$WORK/bob.out"; check $? "unknown recipient reported to sender"

echo "Broadcast"
grep -q "broadcast-from-bob" "$WORK/alice.out"; check $? "broadcast reaches alice"
grep -q "broadcast-from-bob" "$WORK/carol.out"; check $? "broadcast reaches carol"
grep -q "broadcast-from-bob" "$WORK/bob.out"; check_absent $? "broadcast does not echo to sender"

echo "Roster and presence"
grep -q "Online (3)" "$WORK/bob.out"; check $? "/who lists all three clients"
grep -q "carol joined" "$WORK/alice.out"; check $? "join notice delivered"
grep -q "bob left" "$WORK/carol.out"; check $? "leave notice delivered"

echo "Key rotation with relays in flight"
received=$(grep -o "filler-[0-9]*" "$WORK/alice.out" | sort -u | wc -l)
[ "$received" -eq 12 ]; check $? "all 12 relayed messages arrived across the rotation ($received/12)"
grep -q "after-rotation" "$WORK/alice.out"; check $? "traffic still decrypts after rotation"
grep -q "Rotated send key for session" "$WORK/server.log"; check $? "server rotates its own send key"

echo "Client input"
[ "$DAVE_STATUS" -ne 124 ]; check $? "client exits when its input closes"

echo "Server health"
grep -qiE "error|failed" "$WORK/server.log"; check_absent $? "server log is clean"

if [ "$fail" -eq 0 ]; then
    echo "All chat integration tests passed"
    exit 0
fi
echo "$fail integration test(s) failed"
exit 1
