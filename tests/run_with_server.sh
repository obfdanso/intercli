#!/usr/bin/env bash
# Starts the chat server, runs one test program against it, then stops the server.
# Usage: run_with_server.sh <server_exe> <test_exe> [test args...]

set -u

SERVER="$1"
shift

WORK=$(mktemp -d)
"$SERVER" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
    # Stop only the server this script started.
    kill "$SERVER_PID" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# The server generates an RSA key before it listens; wait for its ready line.
for _ in $(seq 1 50); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "server exited early (is port 8080 already in use?)"
        cat "$WORK/server.log"
        exit 1
    fi
    grep -q "Secure server started" "$WORK/server.log" && break
    sleep 0.1
done

if ! grep -q "Secure server started" "$WORK/server.log"; then
    echo "server did not start within 5 seconds"
    cat "$WORK/server.log"
    exit 1
fi

"$@"
status=$?
if [ "$status" -ne 0 ]; then
    echo "--- server log ---"
    cat "$WORK/server.log"
fi
exit "$status"
