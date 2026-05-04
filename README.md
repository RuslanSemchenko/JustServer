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

### DDoS Protection
- Per-IP connection limit (configurable, default 50)
- Header read timeout (default 3s) - drops slow clients
- Maximum request size enforcement (default 8MB)
- Automatic stale connection cleanup

### TLS 1.3 (OpenSSL)
- TLS 1.3 only - no legacy protocol fallback
- Strong ciphersuites: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM
- Certificate/key verification at startup

### Web Application Firewall (WAF)
- **User-Agent blocking**: sqlmap, nikto, nmap, masscan, dirbuster, gobuster, wfuzz, hydra, metasploit, burpsuite, acunetix, and more
- **URI pattern blocking**: path traversal (`../`), SQL injection (`UNION SELECT`, `OR 1=1`), XSS (`<script>`, `javascript:`), RCE (`system()`, `exec()`)
- **Header injection detection**: CRLF injection, null byte injection, oversized headers
- **Body inspection**: XSS and code injection patterns in POST data

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
- Linux (epoll-based)
- C++20 compiler (clang++ recommended)
- CMake 3.20+
- OpenSSL development libraries
- Optional: mold or lld linker

### Build Steps

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install cmake clang libssl-dev

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

This project is currently in an active development and testing phase. The source code is provided for educational and review purposes only. Use, modification, or distribution of this software, in whole or in part, is strictly prohibited without explicit written permission from the author.

As the project is undergoing significant architectural changes and feature enhancements, it is not yet intended for production use.
