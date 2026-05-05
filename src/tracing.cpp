#include "tracing.hpp"
#include "logger.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>

namespace js {

// === Hex helpers ===

static uint8_t hex_char(uint8_t nibble) {
    return nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10);
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static std::string to_hex(const uint8_t* data, size_t len) {
    std::string result(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        result[i * 2] = static_cast<char>(hex_char(data[i] >> 4));
        result[i * 2 + 1] = static_cast<char>(hex_char(data[i] & 0x0F));
    }
    return result;
}

static bool from_hex(std::string_view hex, uint8_t* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        int h = hex_val(hex[i * 2]);
        int l = hex_val(hex[i * 2 + 1]);
        if (h < 0 || l < 0) return false;
        out[i] = static_cast<uint8_t>((h << 4) | l);
    }
    return true;
}

// === TraceContext ===

std::optional<TraceContext> TraceContext::parse(std::string_view traceparent) {
    // Format: "00-<32 hex trace_id>-<16 hex parent_id>-<2 hex flags>"
    // Total length: 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55
    if (traceparent.size() < 55) return std::nullopt;

    TraceContext ctx;

    // Version
    int v1 = hex_val(traceparent[0]);
    int v2 = hex_val(traceparent[1]);
    if (v1 < 0 || v2 < 0) return std::nullopt;
    ctx.version = static_cast<uint8_t>((v1 << 4) | v2);

    if (traceparent[2] != '-') return std::nullopt;

    // Trace ID
    if (!from_hex(traceparent.substr(3, 32), ctx.trace_id.data(), 16)) return std::nullopt;

    if (traceparent[35] != '-') return std::nullopt;

    // Parent ID
    if (!from_hex(traceparent.substr(36, 16), ctx.parent_id.data(), 8)) return std::nullopt;

    if (traceparent[52] != '-') return std::nullopt;

    // Flags
    int f1 = hex_val(traceparent[53]);
    int f2 = hex_val(traceparent[54]);
    if (f1 < 0 || f2 < 0) return std::nullopt;
    ctx.flags = static_cast<uint8_t>((f1 << 4) | f2);

    // Validate trace_id and parent_id are not all zeros
    bool trace_zero = true;
    for (auto b : ctx.trace_id) { if (b != 0) { trace_zero = false; break; } }
    if (trace_zero) return std::nullopt;

    bool parent_zero = true;
    for (auto b : ctx.parent_id) { if (b != 0) { parent_zero = false; break; } }
    if (parent_zero) return std::nullopt;

    return ctx;
}

std::string TraceContext::serialize() const {
    // "00-<trace_id>-<parent_id>-<flags>"
    std::string result;
    result.reserve(55);
    result += to_hex(&version, 1);
    result += '-';
    result += to_hex(trace_id.data(), 16);
    result += '-';
    result += to_hex(parent_id.data(), 8);
    result += '-';
    result += to_hex(&flags, 1);
    return result;
}

TraceContext TraceContext::generate() {
    TraceContext ctx;
    ctx.version = 0;
    ctx.flags = 0x01; // Sampled

    // Generate random trace_id and parent_id
    // Use thread_local RNG for performance
    thread_local std::mt19937_64 rng(std::random_device{}());
    auto gen_bytes = [&](uint8_t* dst, size_t n) {
        for (size_t i = 0; i < n; i += 8) {
            uint64_t val = rng();
            size_t to_copy = (n - i < 8) ? n - i : 8;
            std::memcpy(dst + i, &val, to_copy);
        }
    };

    gen_bytes(ctx.trace_id.data(), 16);
    gen_bytes(ctx.parent_id.data(), 8);

    return ctx;
}

TraceContext TraceContext::create_child() const {
    TraceContext child;
    child.version = version;
    child.trace_id = trace_id; // Same trace
    child.flags = flags;

    // Generate new span ID for the child
    thread_local std::mt19937_64 rng(std::random_device{}());
    uint64_t val = rng();
    std::memcpy(child.parent_id.data(), &val, 8);

    return child;
}

// === Tracer ===

Tracer::Tracer() : rng_(std::random_device{}()) {}

TraceContext Tracer::extract_or_create(const HttpRequest& req) {
    auto tp_header = req.get_header("traceparent");
    if (!tp_header.empty()) {
        auto ctx = TraceContext::parse(tp_header);
        if (ctx) {
            // Create a child span for this server's processing
            return ctx->create_child();
        }
    }

    // No valid traceparent -- start a new trace
    return TraceContext::generate();
}

void Tracer::inject(const TraceContext& ctx, HttpRequest& req) {
    req.headers["traceparent"] = ctx.serialize();
}

void Tracer::inject(const TraceContext& ctx, HttpResponse& resp) {
    resp.headers["traceparent"] = ctx.serialize();
}

Tracer::Span Tracer::start_span(const std::string& operation, const TraceContext& parent) {
    Span span;
    span.context = parent.create_child();
    span.operation_name = operation;
    span.start_time = std::chrono::steady_clock::now();
    return span;
}

void Tracer::finish_span(Span& span) {
    span.end_time = std::chrono::steady_clock::now();
    LOG_DEBUG("Span finished: " + span.operation_name +
              " trace=" + to_hex(span.context.trace_id.data(), 16) +
              " duration=" + std::to_string(span.duration_ms()) + "ms" +
              (span.http_status_code > 0 ? " status=" + std::to_string(span.http_status_code) : ""));
}

} // namespace js
