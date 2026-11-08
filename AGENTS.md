# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.
Rules marked **MUST** / **MUST NOT** are strict. If a task seems to require breaking one, stop and ask.

## Project

JustServer (`js`): a high-performance, security-focused C++20 web server for Linux.
Request pipeline: DDoS guard -> TLS -> HTTP parser -> WAF -> router -> handler (static files / FastCGI / reverse proxy / WASM plugins).
Transports: TCP+TLS 1.3, HTTP/2, HTTP/3 (QUIC via ngtcp2/nghttp3 + GnuTLS). I/O: epoll reactor + worker threads, optional io_uring.

## Toolchain

- Compiler: **Clang 23 only** (`clang++-23`). GCC is rejected by CMake.
- Flags: `-Wall -Wextra -Wpedantic -Werror` (zero-warning policy), C++20, no extensions.
- System deps: OpenSSL 3, zlib, RE2, liburing, Brotli, Zstd, libmaxminddb, GnuTLS, ngtcp2 (+ `ngtcp2_crypto_gnutls`), nghttp3.
- CI (`.github/workflows`): `build.yml` (Release build), `test.yml` (unit tests under ASan+UBSan), `fuzz.yml` (manual libFuzzer runs).

## Build, test, fuzz

```bash
# Release build
cmake -S . -B build -DCMAKE_CXX_COMPILER=clang++-23 -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_FUZZ=OFF
cmake --build build --parallel "$(nproc)"

# Unit tests (ASan + UBSan) - run this before declaring any change done
cmake -S . -B build-test -DCMAKE_CXX_COMPILER=clang++-23 -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTS=ON -DBUILD_FUZZ=OFF -DSANITIZE=ON
cmake --build build-test --target justserver_tests --parallel "$(nproc)"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-test --output-on-failure

# Fuzz targets (libFuzzer)
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++-23 -DBUILD_FUZZ=ON -DBUILD_TESTS=OFF
```

`build/`, `build-fuzz/` and `cmake-build-*/` are git-ignored. Do not commit build output.

## Layout

- `include/*.hpp`, `src/*.cpp`: one module per pair (waf, http_parser, http2, http3, jwt_validator, proxy, load_balancer, cache, acme_client, wasm_interpreter, ...). Everything lives in `namespace js`.
- `src/main.cpp`: CLI + signals only. All other sources are built into the static library `justserver_core` (list in `JS_CORE_SOURCES` in `CMakeLists.txt`).
- `tests/`: unit tests with a tiny in-repo framework (`tests/test_main.cpp`: `TEST`, `ASSERT_TRUE/FALSE/EQ`, some suites expose `run_*_tests()` declared there). `assert()` stays active in tests (`-UNDEBUG`).
- `fuzz/`: libFuzzer targets for http_parser, http2, http3, waf, jwt, fastcgi, wasm.
- `config/justserver.conf`: documented sample config. `www/`: sample static content. `scripts/`: load/chaos/benchmark helpers.

## Code style

- Match the surrounding code. There is no `.clang-format`: do not reformat lines you are not changing.
- `#pragma once`, 4-space indent, `//` comments, `snake_case` functions/variables, `CamelCase` types, trailing underscore for private members (`config_`).
- Logging only through `LOG_DEBUG/INFO/WARN/ERROR` (`logger.hpp`).
- Prefer `std::string_view`, `std::span`, `std::optional`, `std::unique_ptr`, and the arena/slab allocators on hot paths. Exceptions are rare here; do not introduce them on the request path.
- Keep headers light; put implementation in `.cpp`.

## How to add things

- **New source file**: add it to `JS_CORE_SOURCES` in `CMakeLists.txt`.
- **New test file**: add it to the `justserver_tests` target in `CMakeLists.txt` and wire it into `tests/test_main.cpp`.
- **New config key**: add the field with a safe default in `include/config.hpp`, parse it in `src/config.cpp` (with range validation), document it in `config/justserver.conf` and `README.md`, and add a test in `tests/test_config.cpp`. If it must be hot-reloadable (SIGHUP), handle it in `Server` reload code explicitly.
- **New parser or protocol code**: add or extend a fuzz target in `fuzz/` and register it in `CMakeLists.txt` and `fuzz.yml`.

## Security-critical areas (extra care, tests required)

`http_parser`, `http2`, `http3`, `waf`, `jwt_validator`, `file_handler` (path traversal), `fastcgi_client`, `proxy`, `tls_context`, `acme_client`, `ddos_guard`, `wasm_interpreter`/`wasm_plugin`, `anti_bot`, `config`.
Anything here that reads untrusted bytes must bound every length, offset and count before use.

## Rules

### MUST NOT

- Weaken or bypass the build gates: no removing `-Werror`, no new `-Wno-*`, no `#pragma` warning suppressions, no disabling sanitizers, tests or fuzz targets to get a green build. Fix the cause.
- Delete, skip or loosen a failing test to make it pass.
- Commit secrets or key material: `*.pem`, `*.key`, `*.crt`, tokens, private domains or e-mails. Use placeholders.
- Call `system()`, `popen()` or `exec*` (FastCGI stays socket-only), or build shell commands from request data.
- Weaken security defaults: TLS 1.3 only, security headers on, `metrics_localhost_only = true`, HTTP/3, ACME and WASM plugins off by default.
- Convert untrusted or config numbers unsafely: no bare `std::stoi`/`stoull` followed by `static_cast` to an unsigned or narrower type, and no unchecked arithmetic on sizes taken from input. Use range-checked parsing (e.g. `std::from_chars` with explicit min/max).
- Use raw owning `new`/`delete` or `malloc`/`free` in new code.
- Call non-async-signal-safe functions (logging, allocation, locks) from signal handlers; set a flag and handle it in normal context.
- Add dependencies, change the minimum compiler version, or change CMake options/CI workflows without asking.
- Push to `main`, force-push, or rewrite history unless explicitly told to.
- Edit generated or build directories, or reformat unrelated code.

### MUST

- Build with Clang 23 with zero warnings and run the ASan+UBSan unit tests before reporting a task as done.
- Add or update tests for every behavior change and every bug fix (a regression test that fails before the fix).
- Validate all untrusted input: bounds, size limits, encoding. Fail closed.
- Keep `README.md`, `config/justserver.conf` and `include/config.hpp` consistent with each other.
- Say plainly what you could not build, run or verify.
- Write commit messages in English, imperative mood, one logical change per commit.

### Allowed without asking

- Edit `src/`, `include/`, `tests/`, `fuzz/`, docs and the sample config within the scope of the task.
- Add tests and fuzz inputs, and make small refactors inside the module you are changing.
- Run builds, tests, fuzzers, `clang-tidy-23 -p build <changed files>` and `clang-format-23` on files you touched (review diagnostics; do not mass-apply fixes).

### Ask first

- New third-party dependencies or version bumps of ngtcp2/nghttp3/Clang.
- Changes to default config values, wire behavior, public CLI flags or the config file format.
- Large refactors, file moves/deletions, or edits to security-critical modules beyond the task's scope.
- Anything touching CI, release or deployment.
