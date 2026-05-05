#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <cstdint>

namespace js {

// Supported compression algorithms (in preference order)
enum class CompressionAlgo {
    NONE,
    ZSTD,     // Facebook's Zstandard - best ratio/speed tradeoff
    BROTLI,   // Google's Brotli - best ratio for web
    GZIP,     // Legacy fallback
};

// Compression engine supporting Brotli, Zstd, and Gzip on-the-fly
class Compressor {
public:
    // Compress data using the specified algorithm
    // quality: 0-11 for brotli, 1-22 for zstd, 1-9 for gzip
    static std::string compress(std::string_view input, CompressionAlgo algo, int quality = -1);

    // Decompress data (auto-detects format)
    static std::optional<std::string> decompress(std::string_view input, CompressionAlgo algo);

    // Brotli compression/decompression
    static std::string brotli_compress(std::string_view input, int quality = 4);
    static std::optional<std::string> brotli_decompress(std::string_view input);

    // Zstd compression/decompression
    static std::string zstd_compress(std::string_view input, int level = 3);
    static std::optional<std::string> zstd_decompress(std::string_view input);

    // Parse Accept-Encoding header and return the best algorithm we support
    static CompressionAlgo negotiate(std::string_view accept_encoding);

    // Get the Content-Encoding header value for an algorithm
    static std::string_view encoding_name(CompressionAlgo algo);

    // Default quality levels optimized for web serving (speed over ratio)
    static constexpr int BROTLI_FAST_QUALITY = 4;    // Good balance
    static constexpr int BROTLI_BEST_QUALITY = 11;   // Maximum compression
    static constexpr int ZSTD_FAST_LEVEL = 3;        // Good balance
    static constexpr int ZSTD_BEST_LEVEL = 19;       // Maximum compression

    // Minimum size to bother compressing (bytes)
    static constexpr size_t MIN_COMPRESS_SIZE = 256;

    // MIME types worth compressing
    static bool should_compress(std::string_view content_type);
};

// Streaming compressor for chunked transfer encoding
class StreamingCompressor {
public:
    explicit StreamingCompressor(CompressionAlgo algo, int quality = -1);
    ~StreamingCompressor();

    // Non-copyable
    StreamingCompressor(const StreamingCompressor&) = delete;
    StreamingCompressor& operator=(const StreamingCompressor&) = delete;

    // Feed data in, get compressed chunks out
    std::string feed(std::string_view input);

    // Finish compression, flush remaining data
    std::string finish();

private:
    CompressionAlgo algo_;
    void* ctx_ = nullptr; // Algorithm-specific context (BrotliEncoderState*, ZSTD_CCtx*, etc.)
};

} // namespace js
