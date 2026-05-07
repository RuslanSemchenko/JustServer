#!/bin/bash
# JustServer Chaos Test Script
# Simulates: bad network, connection drops, partial writes, malformed data
# Requirements: bash, nc (netcat), curl
# Usage: ./scripts/chaos_test.sh [HOST] [PORT]

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8443}"
PROTO="--insecure"
BASE="https://${HOST}:${PORT}"
TOTAL_PASS=0
TOTAL_FAIL=0

log() { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { ((TOTAL_PASS++)); log "PASS: $1"; }
fail() { ((TOTAL_FAIL++)); log "FAIL: $1"; }

# --- Test 1: Connection reset (RST) ---
test_connection_reset() {
    log "=== Test 1: Connection resets ==="
    local RESETS=50
    local i

    for i in $(seq 1 $RESETS); do
        # Connect and immediately reset (SO_LINGER with timeout 0)
        python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
try:
    s.connect(('${HOST}', ${PORT}))
    s.close()
except:
    pass
" 2>/dev/null &
    done
    wait

    # Server should still be alive
    local CODE
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 5 \
        "${BASE}/" 2>/dev/null || echo "000")

    if [[ "$CODE" == "200" ]]; then
        pass "Server survives $RESETS connection resets (status=$CODE)"
    else
        fail "Server may be affected by connection resets (status=$CODE)"
    fi
}

# --- Test 2: Partial HTTP requests ---
test_partial_requests() {
    log "=== Test 2: Partial HTTP requests ==="
    local PARTIALS=20

    for i in $(seq 1 $PARTIALS); do
        (
            # Send partial request line only (no headers, no body)
            echo -ne "GET / HTT" | \
                timeout 3 nc -w 2 "$HOST" "$PORT" 2>/dev/null || true
        ) &
    done
    wait

    # Send more partial variants
    for i in $(seq 1 $PARTIALS); do
        (
            # Send request line + partial header
            echo -ne "GET / HTTP/1.1\r\nHost: loc" | \
                timeout 3 nc -w 2 "$HOST" "$PORT" 2>/dev/null || true
        ) &
    done
    wait

    # Server should still respond
    local CODE
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 5 \
        "${BASE}/" 2>/dev/null || echo "000")

    if [[ "$CODE" == "200" ]]; then
        pass "Server handles $((PARTIALS*2)) partial requests (status=$CODE)"
    else
        fail "Server affected by partial requests (status=$CODE)"
    fi
}

# --- Test 3: Malformed HTTP requests ---
test_malformed_requests() {
    log "=== Test 3: Malformed HTTP requests ==="
    local SUCCESS=0
    local TOTAL=0

    declare -a PAYLOADS=(
        # Invalid method
        "INVALID / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        # No version
        "GET /\r\nHost: localhost\r\n\r\n"
        # Huge header
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Huge: $(python3 -c 'print("A"*100000)')\r\n\r\n"
        # Null bytes
        "GET /\x00path HTTP/1.1\r\nHost: localhost\r\n\r\n"
        # Double Content-Length (smuggling attempt)
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 100\r\n\r\nhello"
        # Negative Content-Length
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n"
        # HTTP/0.9 request
        "GET /\r\n"
        # Very long URI
        "GET /$(python3 -c 'print("A"*65536)') HTTP/1.1\r\nHost: localhost\r\n\r\n"
        # CRLF injection in header
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Injected: value\r\nEvil: header\r\n\r\n"
        # Tab in method
        "G\tET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )

    for payload in "${PAYLOADS[@]}"; do
        ((TOTAL++))
        echo -ne "$payload" | timeout 3 nc -w 2 "$HOST" "$PORT" >/dev/null 2>&1 && ((SUCCESS++)) || true
    done

    # Server should still be alive after all malformed requests
    local CODE
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 5 \
        "${BASE}/" 2>/dev/null || echo "000")

    if [[ "$CODE" == "200" ]]; then
        pass "Server survives $TOTAL malformed requests (status=$CODE)"
    else
        fail "Server may be affected by malformed requests (status=$CODE)"
    fi
}

# --- Test 4: Partial writes (1 byte at a time) ---
test_partial_writes() {
    log "=== Test 4: Partial writes (byte-by-byte) ==="
    local REQUEST="GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    local CONNS=5

    for c in $(seq 1 $CONNS); do
        (
            python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(('${HOST}', ${PORT}))
    request = b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
    for byte in request:
        s.send(bytes([byte]))
        time.sleep(0.01)  # 10ms between bytes
    response = s.recv(4096)
except Exception as e:
    pass
finally:
    s.close()
" 2>/dev/null
        ) &
    done
    wait

    local CODE
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 5 \
        "${BASE}/" 2>/dev/null || echo "000")

    if [[ "$CODE" == "200" ]]; then
        pass "Server handles partial writes (status=$CODE)"
    else
        fail "Server affected by partial writes (status=$CODE)"
    fi
}

# --- Test 5: Rapid connect/disconnect ---
test_rapid_connect_disconnect() {
    log "=== Test 5: Rapid connect/disconnect (100 connections) ==="
    local CONNS=100

    python3 -c "
import socket, concurrent.futures

def connect_disconnect(i):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('${HOST}', ${PORT}))
        s.close()
        return True
    except:
        return False

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = list(executor.map(connect_disconnect, range(${CONNS})))
    success = sum(results)
    print(f'{success}/${CONNS}')
" 2>/dev/null

    local CODE
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 5 \
        "${BASE}/" 2>/dev/null || echo "000")

    if [[ "$CODE" == "200" ]]; then
        pass "Server survives rapid connect/disconnect (status=$CODE)"
    else
        fail "Server affected by rapid connect/disconnect (status=$CODE)"
    fi
}

# --- Test 6: Mixed good and bad traffic ---
test_mixed_traffic() {
    log "=== Test 6: Mixed good and bad traffic ==="
    local GOOD=0
    local BAD_PIDS=()

    # Launch bad traffic in background
    for i in $(seq 1 20); do
        (
            echo -ne "GARBAGE\x00\xff\xfe\r\n\r\n" | \
                timeout 2 nc -w 1 "$HOST" "$PORT" 2>/dev/null || true
        ) &
        BAD_PIDS+=($!)
    done

    # Simultaneously send good requests
    for i in $(seq 1 30); do
        local CODE
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            $PROTO --connect-timeout 3 --max-time 5 \
            "${BASE}/" 2>/dev/null || echo "000")
        if [[ "$CODE" == "200" ]]; then
            ((GOOD++))
        fi
    done

    # Clean up
    for pid in "${BAD_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    log "  Good requests during bad traffic: $GOOD/30"
    if (( GOOD > 20 )); then
        pass "Mixed traffic resilience ($GOOD/30 good requests succeeded)"
    else
        fail "Mixed traffic resilience ($GOOD/30 good requests succeeded)"
    fi
}

# --- Run all chaos tests ---
log "========================================="
log "JustServer Chaos Test Suite"
log "Target: ${HOST}:${PORT}"
log "========================================="

test_connection_reset
test_partial_requests
test_malformed_requests
test_partial_writes
test_rapid_connect_disconnect
test_mixed_traffic

log "========================================="
log "Results: $TOTAL_PASS passed, $TOTAL_FAIL failed"
log "========================================="

exit $TOTAL_FAIL
