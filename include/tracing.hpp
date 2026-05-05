#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <chrono>
#include <random>
#include <array>
#include <cstdint>
#include <optional>

namespace js {

// W3C Trace Context (https://www.w3.org/TR/trace-context/)
// Implements traceparent header generation and propagation for distributed tracing.
// Compatible with Jaeger, Zipkin, OpenTelemetry, and any W3C-compliant system.
struct TraceContext {
    // Version (currently 00)
    uint8_t version = 0;

    // Trace ID: 16 bytes (128-bit), hex-encoded to 32 chars
    std::array<uint8_t, 16> trace_id{};

    // Parent Span ID: 8 bytes (64-bit), hex-encoded to 16 chars
    std::array<uint8_t, 8> parent_id{};

    // Trace flags (bit 0 = sampled)
    uint8_t flags = 0x01; // Sampled by default

    bool sampled() const { return (flags & 0x01) != 0; }

    // Parse from traceparent header value
    // Format: "00-<trace_id>-<parent_id>-<flags>"
    static std::optional<TraceContext> parse(std::string_view traceparent);

    // Serialize to traceparent header value
    std::string serialize() const;

    // Generate a new trace context (new trace)
    static TraceContext generate();

    // Create a child span (same trace_id, new parent_id)
    TraceContext create_child() const;
};

// Distributed tracing manager for JustServer
// Automatically generates and propagates trace headers through proxy chains.
class Tracer {
public:
    Tracer();

    // Extract trace context from incoming request headers
    // If no traceparent header, generates a new trace
    TraceContext extract_or_create(const HttpRequest& req);

    // Inject trace context into outgoing request/response headers
    void inject(const TraceContext& ctx, HttpRequest& req);
    void inject(const TraceContext& ctx, HttpResponse& resp);

    // Create a span for a request
    struct Span {
        TraceContext context;
        std::string operation_name;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;

        // Span attributes
        std::string http_method;
        std::string http_url;
        int http_status_code = 0;
        std::string peer_address;

        double duration_ms() const {
            return std::chrono::duration<double, std::milli>(end_time - start_time).count();
        }
    };

    // Start a new span
    Span start_span(const std::string& operation, const TraceContext& parent);

    // Finish a span (records it)
    void finish_span(Span& span);

    // Get trace header name
    static constexpr std::string_view TRACEPARENT_HEADER = "traceparent";
    static constexpr std::string_view TRACESTATE_HEADER = "tracestate";

private:
    std::mt19937_64 rng_;
};

} // namespace js
