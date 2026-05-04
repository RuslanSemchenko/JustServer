#!/bin/bash
# JustServer Stress Test Suite using wrk
# Usage: ./scripts/benchmark.sh [host] [port]
#
# Prerequisites:
#   sudo apt install wrk  # or build from https://github.com/wg/wrk

HOST="${1:-127.0.0.1}"
PORT="${2:-8080}"
BASE_URL="http://${HOST}:${PORT}"
DURATION="30s"
THREADS=4
CONNECTIONS=100

echo "========================================"
echo "  JustServer Benchmark Suite"
echo "  Target: ${BASE_URL}"
echo "  Duration: ${DURATION}"
echo "  Threads: ${THREADS}"
echo "  Connections: ${CONNECTIONS}"
echo "========================================"
echo ""

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "ERROR: wrk is not installed. Install it with:"
    echo "  sudo apt install wrk"
    echo "  # or build from https://github.com/wg/wrk"
    exit 1
fi

# Test 1: Static HTML (small file)
echo "--- Test 1: Static HTML (index.html) ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency "${BASE_URL}/index.html"
echo ""

# Test 2: Static JS file
echo "--- Test 2: Static HTML+JS page ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency "${BASE_URL}/test_html_js.html"
echo ""

# Test 3: Metrics endpoint (dynamic)
echo "--- Test 3: Prometheus /metrics endpoint ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency "${BASE_URL}/metrics"
echo ""

# Test 4: 404 handling
echo "--- Test 4: 404 Not Found handling ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency "${BASE_URL}/nonexistent-page.html"
echo ""

# Test 5: High connection count
echo "--- Test 5: High connections (500) ---"
wrk -t${THREADS} -c500 -d${DURATION} \
    --latency "${BASE_URL}/index.html"
echo ""

# Test 6: Pipeline with Lua script (if supported)
cat > /tmp/js_bench_pipeline.lua << 'LUA'
init = function(args)
    local r = {}
    for i = 1, 10 do
        r[i] = wrk.format("GET", "/index.html")
    end
    req = table.concat(r)
end

request = function()
    return req
end
LUA

echo "--- Test 6: HTTP Pipelining (10 requests per connection) ---"
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency -s /tmp/js_bench_pipeline.lua "${BASE_URL}"
echo ""

# Summary
echo "========================================"
echo "  Benchmark complete!"
echo "  Check /metrics for server-side stats:"
echo "  curl ${BASE_URL}/metrics"
echo "========================================"
