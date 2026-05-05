#include "tracing.hpp"
#include <cassert>
#include <iostream>

namespace {

void test_trace_context_generate() {
    auto ctx = js::TraceContext::generate();
    assert(ctx.version == 0);
    assert(ctx.sampled());

    // Trace ID should not be all zeros
    bool all_zero = true;
    for (auto b : ctx.trace_id) { if (b != 0) { all_zero = false; break; } }
    assert(!all_zero);

    std::cout << "  [PASS] trace_context_generate\n";
}

void test_trace_context_serialize_parse() {
    auto original = js::TraceContext::generate();
    auto serialized = original.serialize();

    // Should be 55 chars: "00-<32>-<16>-<2>"
    assert(serialized.size() == 55);
    assert(serialized[0] == '0' && serialized[1] == '0');
    assert(serialized[2] == '-');
    assert(serialized[35] == '-');
    assert(serialized[52] == '-');

    // Parse it back
    auto parsed = js::TraceContext::parse(serialized);
    assert(parsed.has_value());
    assert(parsed->version == original.version);
    assert(parsed->trace_id == original.trace_id);
    assert(parsed->parent_id == original.parent_id);
    assert(parsed->flags == original.flags);

    std::cout << "  [PASS] trace_context_serialize_parse\n";
}

void test_trace_context_child() {
    auto parent = js::TraceContext::generate();
    auto child = parent.create_child();

    // Child should have the same trace ID
    assert(child.trace_id == parent.trace_id);

    // Child should have a different parent ID (new span ID)
    assert(child.parent_id != parent.parent_id);

    // Same flags
    assert(child.flags == parent.flags);

    std::cout << "  [PASS] trace_context_child\n";
}

void test_trace_context_parse_invalid() {
    // Too short
    assert(!js::TraceContext::parse("00-abc-def-01").has_value());

    // Invalid hex
    assert(!js::TraceContext::parse("00-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-ZZZZZZZZZZZZZZZZ-01").has_value());

    // All-zero trace ID
    assert(!js::TraceContext::parse("00-00000000000000000000000000000000-0000000000000001-01").has_value());

    std::cout << "  [PASS] trace_context_parse_invalid\n";
}

void test_tracer_inject() {
    js::Tracer tracer;

    js::HttpRequest req;
    req.method_str = "GET";
    req.uri = "/api/test";

    auto ctx = tracer.extract_or_create(req);

    // Inject into outgoing request
    js::HttpRequest proxy_req;
    tracer.inject(ctx, proxy_req);
    assert(proxy_req.headers.count("traceparent") > 0);
    assert(!proxy_req.headers["traceparent"].empty());

    // Inject into response
    js::HttpResponse resp;
    tracer.inject(ctx, resp);
    assert(resp.headers.count("traceparent") > 0);

    std::cout << "  [PASS] tracer_inject\n";
}

void test_tracer_span() {
    js::Tracer tracer;
    auto ctx = js::TraceContext::generate();

    auto span = tracer.start_span("handle_request", ctx);
    span.http_method = "GET";
    span.http_url = "/test";
    span.http_status_code = 200;

    // Simulate some work
    tracer.finish_span(span);

    assert(span.end_time >= span.start_time);
    assert(span.duration_ms() >= 0.0);
    assert(span.context.trace_id == ctx.trace_id);

    std::cout << "  [PASS] tracer_span\n";
}

} // namespace

void run_tracing_tests() {
    std::cout << "=== Tracing Tests ===\n";
    test_trace_context_generate();
    test_trace_context_serialize_parse();
    test_trace_context_child();
    test_trace_context_parse_invalid();
    test_tracer_inject();
    test_tracer_span();
    std::cout << "=== All tracing tests passed ===\n\n";
}
