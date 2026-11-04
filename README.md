# JustServer (JS)

A high-performance C++20 web server for Linux with built-in security: DDoS protection, Web Application Firewall (WAF), TLS 1.3, and Path Traversal prevention.

## Architecture

```
                    +------------------+
                    |   epoll reactor  |  (Edge Triggered, main thread)
                    |   accept loop   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
         +----v----+   +----v----+   +----v----+
         | Worker  |   | Worker  |   | Worker  |  (Thread pool)
         +----+----+   +----+----+   +----+----+
              |              |              |
         +----v--------------v--------------v----+
         |           Request Pipeline            |
         |  DDoS Guard -> TLS -> HTTP Parser     |
         |  -> WAF -> Router -> Handler          |
         +---+---------------------------+-------+
             |                           |
        +----v----+               +------v------+
        |  Static |               |   FastCGI   |
        |  Files  |               |  (php-fpm)  |
        +---------+               +-------------+
```

## Features

### Network Layer
- **epoll** with Edge Triggered mode for high-performance I/O
- Single reactor thread distributing to worker thread pool
- Non-blocking accepts with `accept4()` and `SOCK_CLOEXEC`

### io_uring Event Loop
- Full io_uring async engine replacing epoll for zero-copy, batched syscalls
- Multishot accept, provided buffer pools, zero-copy send
- Async splice for file-to-socket transfers

### Universal Stream Interface
- IStream abstraction decoupling request logic from transport
- TCP, TLS, HTTP/2, and QUIC streams share one interface

### Arena & Slab Allocators
- Per-request arena allocator with O(1) reset (no malloc/free contention)
- Slab allocator for fixed-size object pools (connection contexts)

### DDoS Protection
- Per-IP connection limit (configurable, default 50)
- Header read timeout (default 5s) - drops slow clients
- Maximum request size enforcement (default 8MB)
- Automatic stale connection cleanup

### TLS 1.3 (OpenSSL)
- TLS 1.3 only - no legacy protocol fallback
- Strong ciphersuites: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM
- Certificate/key verification at startup
- **mTLS support** (New) - mutual TLS for service mesh communication

### Automatic Let's Encrypt
- Optional built-in ACME v2 client with ES256 account signing and HTTP-01 validation
- The server listens on TCP port 80 for `/.well-known/acme-challenge/*` while ACME is enabled
- One certificate is issued for all configured DNS names and renewed before expiry; TLS contexts reload after renewal
- Configure `acme_enabled`, `acme_email`, `acme_domains`, and optionally `acme_storage`, `acme_use_staging`, and `acme_directory_url`
- Public DNS for every configured name must point to the server, inbound TCP port 80 must be reachable, and the process must be able to bind it and write the ACME storage directory
- ACME is disabled by default; enabling it without a reachable port 80 listener prevents server startup

### HTTP/3
- Optional HTTP/3 over QUIC (UDP), disabled by default
- Set `http3_enabled = true`; `http3_port = 0` uses the main listener port
- HTTP/3 requires TLS certificate/key files and allows the server to bind the configured UDP port
- Requests use the same WAF, GeoIP, rate limiting, plugin, routing, and security-header pipeline as HTTP/2
- Open the configured UDP port in the host firewall; TCP access to the same port remains unchanged

### GitHub Actions
- Build and unit-test workflows run automatically for pushes and pull requests to `main`, and can also be started manually from the Actions tab
- The separate **Fuzz** workflow is manual: select a fuzzer (or all targets) and the time budget per target

### Brotli & Zstd Compression
- On-the-fly and streaming compression
- Accept-Encoding negotiation (prefers zstd > br > gzip)
- MIME-type aware (only compresses text-based content)

### Web Application Firewall
- **User-Agent blocking**: sqlmap, nikto, nmap, masscan, dirbuster, gobuster, wfuzz, hydra, metasploit, burpsuite, acunetix, and more
- **URI pattern blocking**: path traversal (`../`), SQL injection (`UNION SELECT`, `OR 1=1`), XSS (`<script>`, `javascript:`), RCE (`system()`, `exec()`)
- **Header injection detection**: CRLF injection, null byte injection, oversized headers
- **Body inspection**: XSS and code injection patterns in POST data
- **Recursive normalization**: double/triple URL encoding, HTML entities, null byte stripping

### JWT Edge Validation
- Validates JWT tokens at the edge (HS256, RS256, ES256)
- Rejects expired/invalid tokens before they reach backends
- Configurable issuer and audience requirements

### Reverse Proxy & Load Balancer
- Multi-backend HTTP proxy with retry, timeout, health checks
- **Round-Robin**, **Least-Connections**, **EWMA** (fastest-right-now), **Consistent Hashing** (session affinity)
- Hop-by-hop header stripping, X-Forwarded-For injection

### LRU Microcache
- In-memory response cache with `stale-while-revalidate`
- Cache-Control header parsing (max-age, s-maxage, no-store)
- Configurable max entries and memory limits

### OpenTelemetry Tracing
- W3C `traceparent` header generation and propagation
- Compatible with Jaeger, Zipkin, and any W3C-compliant system

### Anti-Bot System
- **JA3/JA4 TLS fingerprinting** - passive detection of bots masquerading as browsers
- **Token Bucket rate limiter** - adaptive per-IP/session/fingerprint
- **JS Challenge** - browser verification page blocking scrapers
- **Proof-of-Work** - compute challenge for L7 DDoS mitigation
- **Tarpit** - 1 byte/sec response drip to exhaust scanner connection pools
- **GeoIP country filtering** - country blocking with MaxMind GeoLite2/GeoIP2 `.mmdb` databases

### WASM Plugin System
- Built-in sandboxed interpreter for a documented WebAssembly MVP subset; no Wasmtime/Wasmer runtime dependency
- Exported hooks: `on_request`, `on_response`, `on_route`, `on_auth`, `on_log`
- Linear-memory limits, bounds-checked memory access, call-depth limit, and per-hook instruction/time budgets
- `env`/`justserver` host imports for request/response data, logging, and the shared key-value store
- Supports integer arithmetic, locals, function calls, structured control flow, and integer/float linear-memory loads and stores
- Host string reads use `(output_ptr, capacity) -> byte_length`; string writes use `(ptr, byte_length)`. Header operations take `(name_ptr, name_length, value_ptr, value_length)`.
- WASI, tables/references, globals, start functions, floating-point arithmetic, SIMD, and multi-value are not supported

Plugins are disabled by default. Configure `wasm_enabled = true`,
`wasm_plugin_dir`, `wasm_max_memory_mb`, and `wasm_timeout_ms` in
`config/justserver.conf` to load `.wasm` modules and run their exported hooks.

### Path Traversal Protection
- URI percent-decoding before validation
- Null byte rejection
- `..` sequence rejection
- `std::filesystem::canonical()` resolution (follows symlinks)
- Strict document root boundary validation
- Optional `chroot()` filesystem isolation

### FastCGI (PHP Support)
- Unix socket communication with php-fpm
- Full CGI environment variable forwarding
- Request body streaming
- CGI header parsing (Status, Content-Type, etc.)
- Zero use of `system()` or `exec()` - only socket communication

## Building

### Requirements
- Linux (kernel 5.10+ for io_uring)
- Clang 22+ (zero warnings policy: `-Wall -Wextra -Wpedantic -Werror`)
- CMake 3.20+
- OpenSSL 3.x, RE2, liburing, Brotli, Zstd, libmaxminddb

### Build Steps

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install cmake libssl-dev libre2-dev liburing-dev \
  libbrotli-dev libzstd-dev libmaxminddb-dev pkg-config

# Install Clang 22
wget -q "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.5/LLVM-22.1.5-Linux-X64.tar.xz"
tar xf LLVM-22.1.5-Linux-X64.tar.xz
export PATH="$PWD/LLVM-22.1.5-Linux-X64/bin:$PATH"

# Build
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ ..
make -j$(nproc)
```

### Build with mold linker (faster linking)

```bash
sudo apt install mold
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ ..
make -j$(nproc)
```

## Usage

```bash
# Basic usage (serves from /var/www/html on port 8443)
./justserver

# Custom document root and port, no TLS
./justserver -d ./www -p 8080 --no-tls

# With config file
./justserver -c /etc/justserver/justserver.conf

# All options
./justserver -h
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c <path>` | Config file path | `/etc/justserver/justserver.conf` |
| `-p <port>` | Listen port | `8443` |
| `-d <path>` | Document root | `/var/www/html` |
| `-w <count>` | Worker threads | CPU core count |
| `--no-tls` | Disable TLS | TLS enabled |
| `--no-waf` | Disable WAF | WAF enabled |
| `--no-fcgi` | Disable FastCGI | FastCGI enabled |

### Generate Self-Signed TLS Certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj '/CN=localhost'
```

## Test Pages

The `www/` directory contains test pages:

| File | Description |
|------|-------------|
| `index.html` | Welcome page with server feature overview |
| `test_html_js.html` | HTML + JS tests (DOM, Canvas, Fetch, Workers, Storage) |
| `test_interactive.html` | Interactive JS app (Todo, JSON validator, benchmarks, crypto) |
| `test_css_js.html` | CSS + JS animation tests (particles, waves, matrix, starfield) |
| `test_php.php` | PHP + JS integration test (requires php-fpm) |
| `test_api.php` | REST API endpoint test (requires php-fpm) |

## Configuration

See `config/justserver.conf` for all configuration options.

GeoIP filtering is opt-in. Set `antibot_geoip_enabled = true`, provide
`antibot_geoip_database` with a MaxMind Country or City `.mmdb` file, and list
ISO 3166-1 alpha-2 codes in `antibot_blocked_countries` separated by commas.

## Project Structure

```
.
├── CMakeLists.txt          # Build system
├── config/
│   └── justserver.conf     # Default configuration
├── include/
│   ├── config.hpp          # Configuration struct
│   ├── ddos_guard.hpp      # DDoS protection
│   ├── fastcgi_client.hpp  # FastCGI protocol client
│   ├── file_handler.hpp    # Static file serving
│   ├── http_parser.hpp     # HTTP/1.1 request parser
│   ├── logger.hpp          # Thread-safe logging
│   ├── server.hpp          # Main server (epoll reactor)
│   ├── tls_context.hpp     # OpenSSL TLS wrapper
│   ├── waf.hpp             # Web Application Firewall
│   └── worker.hpp          # Connection handler
├── src/
│   ├── main.cpp            # Entry point
│   ├── config.cpp
│   ├── ddos_guard.cpp
│   ├── fastcgi_client.cpp
│   ├── file_handler.cpp
│   ├── http_parser.cpp
│   ├── logger.cpp
│   ├── server.cpp
│   ├── tls_context.cpp
│   ├── waf.cpp
│   └── worker.cpp
└── www/                    # Test pages
    ├── index.html
    ├── test_html_js.html
    ├── test_interactive.html
    ├── test_css_js.html
    ├── test_php.php
    └── test_api.php
```

## Security Design

- **No `system()` / `exec()` calls** - the server never spawns shell processes
- **Memory-safe C++20** - `std::string_view`, `std::span`, `std::filesystem`, RAII
- **Compiled with `-Werror`** - all warnings are errors
- **SIGPIPE ignored** - no crashes from client disconnects
- **`SOCK_CLOEXEC`** - file descriptors don't leak to child processes
- **`chroot()` support** - filesystem isolation when running as root

## License

Copyright (c) 2026 Ruslan Semchenko. All rights reserved.

Project in active development so dont use this please DONT USE.
