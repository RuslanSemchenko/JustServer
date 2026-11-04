#include "http_client.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

std::string run_local_response(std::string response) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t address_size = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
    uint16_t port = ntohs(address.sin_port);

    std::thread server([listener, response = std::move(response)] {
        int client = accept(listener, nullptr, nullptr);
        assert(client >= 0);
        std::string request;
        char buffer[1024];
        while (request.find("\r\n\r\n") == std::string::npos) {
            ssize_t count = recv(client, buffer, sizeof(buffer), 0);
            assert(count > 0);
            request.append(buffer, static_cast<size_t>(count));
        }
        size_t body_start = request.find("\r\n\r\n") + 4;
        size_t content_length = 0;
        auto header = request.find("Content-Length:");
        if (header != std::string::npos) {
            content_length = static_cast<size_t>(std::stoul(request.substr(header + 15)));
        }
        while (request.size() - body_start < content_length) {
            ssize_t count = recv(client, buffer, sizeof(buffer), 0);
            assert(count > 0);
            request.append(buffer, static_cast<size_t>(count));
        }
        size_t sent = 0;
        while (sent < response.size()) {
            ssize_t count = send(client, response.data() + sent, response.size() - sent,
                                 MSG_NOSIGNAL);
            assert(count > 0);
            sent += static_cast<size_t>(count);
        }
        shutdown(client, SHUT_RDWR);
        close(client);
        close(listener);
    });

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/test?q=1";
    js::HttpClient client;
    auto result = client.get(url);
    server.join();
    assert(result.has_value());
    assert(client.last_error().empty());
    return result->body;
}

} // namespace

void run_http_client_tests() {
    auto parsed = js::HttpClient::parse_url("HTTPS://Example.COM:8443/path?q=1#fragment");
    assert(parsed);
    assert(parsed->scheme == "https");
    assert(parsed->host == "example.com");
    assert(parsed->port == 8443);
    assert(parsed->target == "/path?q=1");
    assert(parsed->host_header() == "example.com:8443");

    parsed = js::HttpClient::parse_url("http://[::1]:8080?x=2");
    assert(parsed && parsed->ipv6_literal);
    assert(parsed->host == "::1");
    assert(parsed->target == "/?x=2");
    assert(parsed->host_header() == "[::1]:8080");

    assert(!js::HttpClient::parse_url("ftp://example.com/"));
    assert(!js::HttpClient::parse_url("http://user@example.com/"));
    assert(!js::HttpClient::parse_url("http://example.com:99999/"));
    assert(!js::HttpClient::parse_url("http://example.com/a b"));

    auto body = run_local_response(
        "HTTP/1.1 201 Created\r\nContent-Length: 5\r\nX-Trace: a\r\n"
        "x-trace: b\r\nConnection: close\r\n\r\nhello");
    assert(body == "hello");

    body = run_local_response(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        "4\r\nWiki\r\n5;ext=ok\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n");
    assert(body == "Wikipedia");

    js::HttpClient client;
    auto response = client.request("GET", "file:///etc/passwd");
    assert(!response);
    assert(!client.last_error().empty());
    std::cout << "  [PASS] HTTP client URL and response parsing\n";
}
