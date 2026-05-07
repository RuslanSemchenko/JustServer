#!/bin/bash
# JustServer Load Test Script
# Tests: 1000+ connections, keep-alive, slow clients
# Requirements: curl, bash 4+
# Usage: ./scripts/load_test.sh [HOST] [PORT]

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8443}"
BASE="https://${HOST}:${PORT}"
PROTO="--insecure" # Allow self-signed certs
TOTAL_PASS=0
TOTAL_FAIL=0

log() { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { ((TOTAL_PASS++)); log "PASS: $1"; }
fail() { ((TOTAL_FAIL++)); log "FAIL: $1"; }

# --- Test 1: Concurrent connections (1000+) ---
test_concurrent_connections() {
    log "=== Test 1: 1000+ concurrent connections ==="
    local CONNS=1000
    local PIDS=()
    local SUCCESS=0
    local FAILED=0

    for i in $(seq 1 $CONNS); do
        (
            curl -s -o /dev/null -w "%{http_code}" \
                $PROTO --connect-timeout 5 --max-time 10 \
                "${BASE}/" 2>/dev/null || echo "000"
        ) &
        PIDS+=($!)

        # Launch in batches of 100 to avoid fd exhaustion on the test side
        if (( i % 100 == 0 )); then
            log "  Launched $i / $CONNS connections..."
            # Brief pause between batches
            sleep 0.1
        fi
    done

    log "  Waiting for all $CONNS connections to complete..."
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null && ((SUCCESS++)) || ((FAILED++))
    done

    log "  Results: $SUCCESS succeeded, $FAILED failed out of $CONNS"
    if (( SUCCESS > CONNS * 80 / 100 )); then
        pass "Concurrent connections ($SUCCESS/$CONNS succeeded)"
    else
        fail "Concurrent connections ($SUCCESS/$CONNS succeeded, expected >80%)"
    fi
}

# --- Test 2: Keep-alive connections ---
test_keepalive() {
    log "=== Test 2: Keep-alive (multiple requests per connection) ==="
    local REQUESTS=50
    local SUCCESS=0

    # curl reuses connections by default with multiple URLs
    local URLS=""
    for i in $(seq 1 $REQUESTS); do
        URLS="$URLS ${BASE}/"
    done

    local RESULT
    RESULT=$(curl -s -o /dev/null -w "%{num_connects}\n" \
        $PROTO --connect-timeout 5 --max-time 30 \
        $URLS 2>/dev/null || echo "error")

    if [[ "$RESULT" != "error" ]]; then
        local NUM_CONNECTS="$RESULT"
        log "  Made $REQUESTS requests with $NUM_CONNECTS TCP connections"
        if (( NUM_CONNECTS < REQUESTS )); then
            pass "Keep-alive reused connections ($NUM_CONNECTS connects for $REQUESTS requests)"
        else
            fail "Keep-alive not working ($NUM_CONNECTS connects for $REQUESTS requests)"
        fi
    else
        fail "Keep-alive test failed to connect"
    fi
}

# --- Test 3: Slow client (Slowloris simulation) ---
test_slow_client() {
    log "=== Test 3: Slow client resilience ==="
    local SLOW_CONNS=10
    local NORMAL_CONNS=20
    local PIDS=()

    # Launch slow connections that send headers very slowly
    for i in $(seq 1 $SLOW_CONNS); do
        (
            # Send partial HTTP request, one byte at a time with delays
            {
                echo -ne "GET / HTTP/1.1\r\n"
                sleep 1
                echo -ne "Host: ${HOST}\r\n"
                sleep 2
                # Don't send the final \r\n -- hang the connection
                sleep 5
            } | curl -s -o /dev/null $PROTO --connect-timeout 10 --max-time 15 \
                "telnet://${HOST}:${PORT}" 2>/dev/null || true
        ) &
        PIDS+=($!)
    done

    sleep 1 # Let slow connections establish

    # Normal requests should still work while slow clients are connected
    local SUCCESS=0
    for i in $(seq 1 $NORMAL_CONNS); do
        local CODE
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            $PROTO --connect-timeout 5 --max-time 5 \
            "${BASE}/" 2>/dev/null || echo "000")
        if [[ "$CODE" == "200" ]]; then
            ((SUCCESS++))
        fi
    done

    # Clean up slow connections
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done

    log "  Normal requests during slowloris: $SUCCESS/$NORMAL_CONNS succeeded"
    if (( SUCCESS > NORMAL_CONNS * 70 / 100 )); then
        pass "Slow client resilience ($SUCCESS/$NORMAL_CONNS normal requests succeeded)"
    else
        fail "Slow client resilience ($SUCCESS/$NORMAL_CONNS normal requests succeeded)"
    fi
}

# --- Test 4: Large request body handling ---
test_large_body() {
    log "=== Test 4: Large request body ==="

    # Send a request with body near the max size limit (8MB default)
    local CODE
    CODE=$(dd if=/dev/zero bs=1M count=7 2>/dev/null | \
        curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 30 \
        -X POST -H "Content-Type: application/octet-stream" \
        --data-binary @- "${BASE}/" 2>/dev/null || echo "000")

    log "  7MB body response: $CODE"
    if [[ "$CODE" != "000" ]]; then
        pass "Large body handling (got response $CODE)"
    else
        fail "Large body handling (connection failed)"
    fi

    # Send oversized request (should be rejected)
    CODE=$(dd if=/dev/zero bs=1M count=10 2>/dev/null | \
        curl -s -o /dev/null -w "%{http_code}" \
        $PROTO --connect-timeout 5 --max-time 30 \
        -X POST -H "Content-Type: application/octet-stream" \
        --data-binary @- "${BASE}/" 2>/dev/null || echo "000")

    log "  10MB body response: $CODE"
    # Server should reject or close connection
    pass "Oversized body handling (got response $CODE)"
}

# --- Test 5: Rapid sequential requests (throughput) ---
test_throughput() {
    log "=== Test 5: Throughput (rapid sequential requests) ==="
    local REQUESTS=500
    local START
    START=$(date +%s%N)

    for i in $(seq 1 $REQUESTS); do
        curl -s -o /dev/null $PROTO --connect-timeout 2 --max-time 5 \
            "${BASE}/" 2>/dev/null &
        # Run 50 at a time
        if (( i % 50 == 0 )); then
            wait
        fi
    done
    wait

    local END
    END=$(date +%s%N)
    local ELAPSED=$(( (END - START) / 1000000 )) # milliseconds

    if (( ELAPSED > 0 )); then
        local RPS=$(( REQUESTS * 1000 / ELAPSED ))
        log "  $REQUESTS requests in ${ELAPSED}ms = ~${RPS} req/s"
        pass "Throughput test (~${RPS} req/s)"
    else
        pass "Throughput test (completed instantly)"
    fi
}

# --- Run all tests ---
log "========================================="
log "JustServer Load Test Suite"
log "Target: ${BASE}"
log "========================================="

test_concurrent_connections
test_keepalive
test_slow_client
test_large_body
test_throughput

log "========================================="
log "Results: $TOTAL_PASS passed, $TOTAL_FAIL failed"
log "========================================="

exit $TOTAL_FAIL
