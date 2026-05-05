#include "proxy.hpp"
#include "logger.hpp"
#include "metrics.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <algorithm>

namespace js {

ReverseProxy::ReverseProxy() = default;
ReverseProxy::~ReverseProxy() = default;

void ReverseProxy::add_route(ProxyRoute route) {
    std::string prefix = route.prefix;

    // Store the route first (move backends into stable storage)
    routes_.push_back(std::move(route));

    // Sort routes by prefix length (longest first) for matching
    std::sort(routes_.begin(), routes_.end(), [](const ProxyRoute& a, const ProxyRoute& b) {
        return a.prefix.size() > b.prefix.size();
    });

    // Find the stored route (may have moved during sort) and create LB from it
    for (auto& r : routes_) {
        if (r.prefix == prefix) {
            auto lb = LoadBalancer::create(r.lb_algorithm, r.backends);
            load_balancers_[prefix] = std::move(lb);
            break;
        }
    }

    LOG_INFO("Proxy route added: " + prefix + " -> backends configured");
}

bool ReverseProxy::matches(const HttpRequest& req) const {
    return find_route(req) != nullptr;
}

const ProxyRoute* ReverseProxy::find_route(const HttpRequest& req) const {
    for (const auto& route : routes_) {
        if (req.path.starts_with(route.prefix)) {
            return &route;
        }
    }
    return nullptr;
}

std::optional<HttpResponse> ReverseProxy::proxy_request(const HttpRequest& req,
                                                          const std::string& client_ip) {
    const auto* route = find_route(req);
    if (!route) return std::nullopt;

    // Check cache first
    if (route->cache_enabled) {
        auto cache_key = HttpCache::build_key(req);
        auto cached = cache_.get(cache_key);
        if (cached) {
            LOG_DEBUG("Cache hit for " + req.uri);
            return cached;
        }
    }

    // Select a backend
    auto lb_it = load_balancers_.find(route->prefix);
    if (lb_it == load_balancers_.end()) return std::nullopt;

    // Try with retries
    for (int attempt = 0; attempt <= route->max_retries; ++attempt) {
        // Use client IP as key for consistent hashing
        Backend* backend = lb_it->second->select(client_ip);
        if (!backend) {
            LOG_ERROR("No healthy backends for route: " + route->prefix);
            return HttpResponse::make_error(502, "No healthy backends available");
        }

        auto start = std::chrono::steady_clock::now();
        auto result = forward_to_backend(req, backend, *route, client_ip);
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed);

        if (result) {
            lb_it->second->report_result(backend, latency, true);

            // Cache the response if cacheable
            if (route->cache_enabled && HttpCache::is_cacheable(req, *result)) {
                cache_.put(HttpCache::build_key(req), *result, route->cache_ttl);
            }

            return result;
        }

        lb_it->second->report_result(backend, latency, false);
        LOG_WARN("Backend " + backend->address + " failed, attempt " +
                 std::to_string(attempt + 1) + "/" + std::to_string(route->max_retries + 1));
    }

    return HttpResponse::make_error(502, "All backend attempts failed");
}

std::optional<HttpResponse> ReverseProxy::forward_to_backend(const HttpRequest& req,
                                                               Backend* backend,
                                                               const ProxyRoute& route,
                                                               const std::string& client_ip) {
    auto proxy_req = build_proxy_request(req, route, *backend, client_ip);
    return do_http_request(proxy_req, *backend, route);
}

HttpRequest ReverseProxy::build_proxy_request(const HttpRequest& req, const ProxyRoute& route,
                                                const Backend& backend,
                                                const std::string& client_ip) {
    HttpRequest proxy_req = req;

    // Set Host header to backend
    proxy_req.headers["Host"] = backend.host + ":" + std::to_string(backend.port);

    // Strip hop-by-hop headers (RFC 2616 Section 13.5.1)
    // These must not be forwarded to the backend
    static const std::vector<std::string> hop_by_hop = {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "TE", "Trailers", "Transfer-Encoding", "Upgrade"
    };
    for (const auto& h : hop_by_hop) {
        proxy_req.headers.erase(h);
    }

    // Add X-Forwarded-* headers
    proxy_req.headers["X-Forwarded-For"] = client_ip;
    proxy_req.headers["X-Forwarded-Proto"] = "https";
    proxy_req.headers["X-Real-IP"] = client_ip;

    // Add custom headers from route config
    for (const auto& [key, value] : route.add_headers) {
        proxy_req.headers[key] = value;
    }

    // Remove headers as configured
    for (const auto& key : route.remove_headers) {
        proxy_req.headers.erase(key);
    }

    return proxy_req;
}

std::optional<HttpResponse> ReverseProxy::do_http_request(const HttpRequest& req,
                                                            const Backend& backend,
                                                            const ProxyRoute& route) {
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return std::nullopt;

    // Set TCP_NODELAY
    int opt = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // Connect with timeout
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(backend.port);
    if (inet_pton(AF_INET, backend.host.c_str(), &addr.sin_addr) <= 0) {
        close(sockfd);
        return std::nullopt;
    }

    // Non-blocking connect
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return std::nullopt;
    }

    // Wait for connection
    struct pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLOUT;
    int timeout_ms = static_cast<int>(route.connect_timeout.count());
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        close(sockfd);
        return std::nullopt;
    }

    // Check connection result
    int error = 0;
    socklen_t errlen = sizeof(error);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &errlen);
    if (error != 0) {
        close(sockfd);
        return std::nullopt;
    }

    // Set back to blocking with timeout
    fcntl(sockfd, F_SETFL, flags);
    struct timeval tv{};
    tv.tv_sec = route.read_timeout.count() / 1000;
    tv.tv_usec = static_cast<long>((route.read_timeout.count() % 1000) * 1000);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Build HTTP request
    std::string raw_req = req.method_str + " " + req.uri + " HTTP/1.1\r\n";
    for (const auto& [key, value] : req.headers) {
        raw_req += key + ": " + value + "\r\n";
    }
    raw_req += "Connection: close\r\n\r\n";
    if (!req.body.empty()) {
        raw_req += req.body;
    }

    // Send request
    size_t sent = 0;
    while (sent < raw_req.size()) {
        auto n = send(sockfd, raw_req.data() + sent, raw_req.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) { close(sockfd); return std::nullopt; }
        sent += static_cast<size_t>(n);
    }

    // Read response
    std::string response_data;
    char buf[8192];
    while (true) {
        auto n = recv(sockfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response_data.append(buf, static_cast<size_t>(n));
    }
    close(sockfd);

    if (response_data.empty()) return std::nullopt;

    // Parse response (minimal HTTP response parser)
    HttpResponse resp;
    auto header_end = response_data.find("\r\n\r\n");
    if (header_end == std::string::npos) return std::nullopt;

    // Parse status line
    auto first_line_end = response_data.find("\r\n");
    auto status_line = std::string_view(response_data).substr(0, first_line_end);
    auto sp1 = status_line.find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    auto sp2 = status_line.find(' ', sp1 + 1);
    auto code_str = status_line.substr(sp1 + 1, sp2 - sp1 - 1);
    resp.status_code = 0;
    for (char c : code_str) {
        if (c >= '0' && c <= '9') resp.status_code = resp.status_code * 10 + (c - '0');
    }
    if (sp2 != std::string_view::npos) {
        resp.status_text = std::string(status_line.substr(sp2 + 1));
    }

    // Parse headers
    size_t pos = first_line_end + 2;
    while (pos < header_end) {
        auto line_end = response_data.find("\r\n", pos);
        if (line_end == std::string::npos || line_end > header_end) break;
        auto line = std::string_view(response_data).substr(pos, line_end - pos);
        auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            auto name = std::string(line.substr(0, colon));
            auto value = line.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
            resp.headers[name] = std::string(value);
        }
        pos = line_end + 2;
    }

    // Body
    resp.body = response_data.substr(header_end + 4);

    // Remove hop-by-hop headers
    resp.headers.erase("Transfer-Encoding");
    resp.headers.erase("Connection");

    return resp;
}

} // namespace js
