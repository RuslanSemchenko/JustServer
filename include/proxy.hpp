#pragma once

#include "http_parser.hpp"
#include "load_balancer.hpp"
#include "cache.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>
#include <chrono>

namespace js {

// Reverse proxy configuration for a route
struct ProxyRoute {
    std::string prefix;                // URL prefix to match (e.g., "/api")
    std::vector<Backend> backends;     // Backend servers
    LBAlgorithm lb_algorithm = LBAlgorithm::ROUND_ROBIN;

    // Timeouts
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds read_timeout{30000};
    std::chrono::milliseconds write_timeout{30000};

    // Retry policy
    int max_retries = 2;

    // Header manipulation
    std::unordered_map<std::string, std::string> add_headers;   // Headers to add
    std::vector<std::string> remove_headers;                    // Headers to strip

    // Protocol support
    bool websocket_passthrough = true;
    bool grpc_passthrough = true;

    // Caching
    bool cache_enabled = false;
    std::chrono::seconds cache_ttl{60};
};

// Multi-backend reverse proxy supporting HTTP, WebSocket, gRPC pass-through.
// Routes requests to appropriate backend pools based on URL prefix.
class ReverseProxy {
public:
    ReverseProxy();
    ~ReverseProxy();

    // Add a proxy route
    void add_route(ProxyRoute route);

    // Try to proxy a request. Returns nullopt if no route matches.
    std::optional<HttpResponse> proxy_request(const HttpRequest& req,
                                               const std::string& client_ip);

    // Check if a request matches any proxy route
    bool matches(const HttpRequest& req) const;

    // Get the matching route for a request
    const ProxyRoute* find_route(const HttpRequest& req) const;

    // Get cache reference (for metrics/management)
    HttpCache& cache() { return cache_; }

private:
    // Forward request to a backend
    std::optional<HttpResponse> forward_to_backend(const HttpRequest& req,
                                                     Backend* backend,
                                                     const ProxyRoute& route,
                                                     const std::string& client_ip);

    // Build the proxied request (rewrite headers)
    HttpRequest build_proxy_request(const HttpRequest& req, const ProxyRoute& route,
                                     const Backend& backend, const std::string& client_ip);

    // Perform the actual HTTP connection to the backend
    std::optional<HttpResponse> do_http_request(const HttpRequest& req,
                                                  const Backend& backend,
                                                  const ProxyRoute& route);

    std::vector<ProxyRoute> routes_;
    std::unordered_map<std::string, std::unique_ptr<LoadBalancer>> load_balancers_;
    HttpCache cache_;
};

} // namespace js
