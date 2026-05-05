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

} // namespace

void run_compression_tests() {
    std::cout << "=== Compression Tests ===\n";
    test_brotli_compress_decompress();
    test_zstd_compress_decompress();
    test_negotiate_encoding();
    test_should_compress();
    test_streaming_compressor();
    std::cout << "=== All compression tests passed ===\n\n";
}
