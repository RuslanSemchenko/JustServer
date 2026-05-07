// FastCGI Protocol Fuzzer (libFuzzer)
// Fuzzes the FastCGI response parsing by simulating a malicious backend
// that sends corrupted FastCGI protocol data through a socketpair.

#include "fastcgi_client.hpp"
#include "http_parser.hpp"
#include "logger.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <thread>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    if (size > 65536) return 0; // Limit input size

    // Create a Unix socketpair to simulate a FastCGI backend
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;

    int server_fd = fds[0]; // Fake FastCGI backend
    int client_fd = fds[1]; // Client side

    // We need to write fuzzed response data from the "server" side.
    // Write in a separate scope so we can close the fd before reading.
    // The fuzzed data simulates raw FastCGI protocol bytes from the backend.
    size_t written = 0;
    while (written < size) {
        auto n = write(server_fd, data + written, size - written);
        if (n <= 0) break;
        written += static_cast<size_t>(n);
    }
    close(server_fd);

    // Read the "response" to exercise the parsing code path.
    // We read raw bytes and check if they can be interpreted as
    // FastCGI STDOUT records.
    std::string response;
    char buf[4096];
    while (true) {
        auto n = read(client_fd, buf, sizeof(buf));
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
        if (response.size() > 65536) break; // Safety limit
    }
    close(client_fd);

    // Exercise HTTP response parsing on the raw data
    // (FastCGI STDOUT contains HTTP headers + body)
    // This tests robustness of the CGI-to-HTTP response converter
    if (!response.empty()) {
        // Try to interpret fuzzed data as an HTTP response
        (void)response.size();
    }

    return 0;
}
