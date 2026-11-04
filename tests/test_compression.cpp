#include "compression.hpp"
#include <cassert>
#include <iostream>
#include <string>

namespace {

void test_brotli_compress_decompress() {
    std::string original = "Hello, World! This is a test of Brotli compression. "
                           "We need enough data to make compression worthwhile. "
                           "Repeating patterns help: abcabc abcabc abcabc abcabc.";

    auto compressed = js::Compressor::brotli_compress(original);
    assert(!compressed.empty());
    assert(compressed.size() < original.size()); // Should actually compress

    auto decompressed = js::Compressor::brotli_decompress(compressed);
    assert(decompressed.has_value());
    assert(*decompressed == original);

    std::cout << "  [PASS] brotli_compress_decompress (" << original.size()
              << " -> " << compressed.size() << " bytes)\n";
}

void test_zstd_compress_decompress() {
    std::string original = "Hello, World! This is a test of Zstandard compression. "
                           "Repeating data compresses well: xyzxyz xyzxyz xyzxyz.";

    auto compressed = js::Compressor::zstd_compress(original);
    assert(!compressed.empty());

    auto decompressed = js::Compressor::zstd_decompress(compressed);
    assert(decompressed.has_value());
    assert(*decompressed == original);

    std::cout << "  [PASS] zstd_compress_decompress (" << original.size()
              << " -> " << compressed.size() << " bytes)\n";
}

void test_negotiate_encoding() {
    // Prefer zstd
    auto algo1 = js::Compressor::negotiate("br, gzip, zstd");
    assert(algo1 == js::CompressionAlgo::ZSTD);

    // Explicit quality preference
    auto algo2 = js::Compressor::negotiate("gzip;q=1.0, br;q=0.8");
    assert(algo2 == js::CompressionAlgo::GZIP);

    // Only brotli
    auto algo3 = js::Compressor::negotiate("br");
    assert(algo3 == js::CompressionAlgo::BROTLI);

    // No supported encoding
    auto algo4 = js::Compressor::negotiate("deflate");
    assert(algo4 == js::CompressionAlgo::NONE);

    std::cout << "  [PASS] negotiate_encoding\n";
}

void test_should_compress() {
    assert(js::Compressor::should_compress("text/html"));
    assert(js::Compressor::should_compress("application/json"));
    assert(js::Compressor::should_compress("application/javascript"));
    assert(js::Compressor::should_compress("text/css; charset=utf-8"));
    assert(js::Compressor::should_compress("image/svg+xml"));
    assert(!js::Compressor::should_compress("image/png"));
    assert(!js::Compressor::should_compress("video/mp4"));

    std::cout << "  [PASS] should_compress\n";
}

void test_streaming_compressor() {
    js::StreamingCompressor compressor(js::CompressionAlgo::ZSTD);

    std::string chunk1 = "First chunk of data for streaming compression. ";
    std::string chunk2 = "Second chunk of data for streaming compression. ";
    std::string chunk3 = "Third and final chunk of data.";

    std::string compressed;
    compressed += compressor.feed(chunk1);
    compressed += compressor.feed(chunk2);
    compressed += compressor.feed(chunk3);
    compressed += compressor.finish();

    assert(!compressed.empty());

    // Should decompress to the original concatenated data
    auto original = chunk1 + chunk2 + chunk3;
    auto decompressed = js::Compressor::zstd_decompress(compressed);
    assert(decompressed.has_value());
    assert(*decompressed == original);

    std::cout << "  [PASS] streaming_compressor\n";
}

void test_gzip_compress_decompress() {
    std::string original;
    for (int i = 0; i < 200; ++i) {
        original += "Line " + std::to_string(i) + ": gzip is the legacy fallback encoding.\n";
    }

    auto compressed = js::Compressor::gzip_compress(original);
    assert(compressed.size() > 18);
    assert(compressed.size() < original.size());
    // RFC 1952 magic bytes
    assert(static_cast<unsigned char>(compressed[0]) == 0x1f);
    assert(static_cast<unsigned char>(compressed[1]) == 0x8b);

    auto decompressed = js::Compressor::gzip_decompress(compressed);
    assert(decompressed.has_value());
    assert(*decompressed == original);

    // Generic interface uses gzip too
    auto generic = js::Compressor::compress(original, js::CompressionAlgo::GZIP);
    auto generic_back = js::Compressor::decompress(generic, js::CompressionAlgo::GZIP);
    assert(generic_back.has_value() && *generic_back == original);

    // Empty input round-trips
    auto empty = js::Compressor::gzip_compress("");
    auto empty_back = js::Compressor::gzip_decompress(empty);
    assert(empty_back.has_value() && empty_back->empty());

    std::cout << "  [PASS] gzip_compress_decompress (" << original.size()
              << " -> " << compressed.size() << " bytes)\n";
}

void test_gzip_corrupt_and_truncated() {
    std::string original(4096, 'x');
    auto compressed = js::Compressor::gzip_compress(original);

    // Truncated stream must fail cleanly
    auto truncated = compressed.substr(0, compressed.size() / 2);
    assert(!js::Compressor::gzip_decompress(truncated).has_value());

    // Garbage must fail cleanly
    assert(!js::Compressor::gzip_decompress("definitely not gzip data").has_value());

    // Concatenated gzip members decode to the concatenation (RFC 1952 2.2)
    auto two = js::Compressor::gzip_compress("hello ") + js::Compressor::gzip_compress("world");
    auto both = js::Compressor::gzip_decompress(two);
    assert(both.has_value() && *both == "hello world");

    std::cout << "  [PASS] gzip_corrupt_and_truncated\n";
}

void test_decompression_bomb_limits() {
    // 8 MB of zeros compresses to a few KB -- decompressing with a 1 MB cap must fail
    std::string zeros(8 * 1024 * 1024, '\0');
    const size_t limit = 1024 * 1024;

    auto gz = js::Compressor::gzip_compress(zeros, 1);
    assert(!js::Compressor::gzip_decompress(gz, limit).has_value());
    assert(js::Compressor::gzip_decompress(gz).has_value());

    auto br = js::Compressor::brotli_compress(zeros, 1);
    assert(!js::Compressor::brotli_decompress(br, limit).has_value());

    auto zs = js::Compressor::zstd_compress(zeros, 1);
    assert(!js::Compressor::zstd_decompress(zs, limit).has_value());

    std::cout << "  [PASS] decompression_bomb_limits\n";
}

void test_streaming_gzip_and_unknown_size_zstd() {
    std::string original;
    std::string compressed;
    js::StreamingCompressor gz(js::CompressionAlgo::GZIP);
    for (int i = 0; i < 100; ++i) {
        std::string chunk = "chunk-" + std::to_string(i) + " streaming gzip payload; ";
        original += chunk;
        compressed += gz.feed(chunk);
    }
    compressed += gz.finish();
    auto back = js::Compressor::gzip_decompress(compressed);
    assert(back.has_value() && *back == original);

    // Streaming zstd output has no content size in the frame header:
    // the decoder must fall back to streaming decompression.
    js::StreamingCompressor zs(js::CompressionAlgo::ZSTD);
    std::string zcompressed = zs.feed(original) + zs.finish();
    auto zback = js::Compressor::zstd_decompress(zcompressed);
    assert(zback.has_value() && *zback == original);

    // Multiple concatenated zstd frames
    auto multi = js::Compressor::zstd_compress("frame-one ") + js::Compressor::zstd_compress("frame-two");
    auto multi_back = js::Compressor::zstd_decompress(multi);
    assert(multi_back.has_value() && *multi_back == "frame-one frame-two");

    std::cout << "  [PASS] streaming_gzip_and_unknown_size_zstd\n";
}

void test_negotiate_gzip_and_wildcard() {
    assert(js::Compressor::negotiate("gzip") == js::CompressionAlgo::GZIP);
    assert(js::Compressor::negotiate("x-gzip, deflate") == js::CompressionAlgo::GZIP);
    assert(js::Compressor::negotiate("*") == js::CompressionAlgo::ZSTD);
    assert(js::Compressor::negotiate("gzip;q=0, br;q=0") == js::CompressionAlgo::NONE);
    assert(js::Compressor::encoding_name(js::CompressionAlgo::GZIP) == "gzip");

    std::cout << "  [PASS] negotiate_gzip_and_wildcard\n";
}

} // namespace

void run_compression_tests() {
    std::cout << "=== Compression Tests ===\n";
    test_brotli_compress_decompress();
    test_zstd_compress_decompress();
    test_negotiate_encoding();
    test_should_compress();
    test_streaming_compressor();
    test_gzip_compress_decompress();
    test_gzip_corrupt_and_truncated();
    test_decompression_bomb_limits();
    test_streaming_gzip_and_unknown_size_zstd();
    test_negotiate_gzip_and_wildcard();
    std::cout << "=== All compression tests passed ===\n\n";
}
