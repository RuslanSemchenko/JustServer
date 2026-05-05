#include "compression.hpp"
#include "logger.hpp"

#include <brotli/encode.h>
#include <brotli/decode.h>
#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <cctype>

namespace js {

// === Static helpers ===

std::string_view Compressor::encoding_name(CompressionAlgo algo) {
    switch (algo) {
        case CompressionAlgo::BROTLI: return "br";
        case CompressionAlgo::ZSTD:   return "zstd";
        case CompressionAlgo::GZIP:   return "gzip";
        default: return "";
    }
}

bool Compressor::should_compress(std::string_view content_type) {
    // Extract the MIME type (before any ;charset= etc.)
    auto semi = content_type.find(';');
    auto mime = content_type.substr(0, semi);

    // Always compress text-based content
    if (mime.starts_with("text/")) return true;
    if (mime == "application/json") return true;
    if (mime == "application/xml") return true;
    if (mime == "application/javascript") return true;
    if (mime == "application/x-javascript") return true;
    if (mime == "application/wasm") return true;
    if (mime == "image/svg+xml") return true;
    if (mime == "application/xhtml+xml") return true;
    if (mime == "application/rss+xml") return true;
    if (mime == "application/atom+xml") return true;
    if (mime == "font/ttf") return true;
    if (mime == "font/otf") return true;
    if (mime == "application/vnd.ms-fontobject") return true;

    return false;
}

CompressionAlgo Compressor::negotiate(std::string_view accept_encoding) {
    // Parse Accept-Encoding header, prefer zstd > br > gzip
    // Format: "br;q=1.0, gzip;q=0.8, zstd;q=0.9"

    struct Encoding {
        CompressionAlgo algo;
        float quality;
    };

    std::vector<Encoding> supported;

    // Tokenize by comma
    size_t pos = 0;
    while (pos < accept_encoding.size()) {
        // Skip whitespace
        while (pos < accept_encoding.size() && accept_encoding[pos] == ' ') ++pos;

        auto comma = accept_encoding.find(',', pos);
        auto token = accept_encoding.substr(pos, comma == std::string_view::npos ? comma : comma - pos);
        pos = (comma == std::string_view::npos) ? accept_encoding.size() : comma + 1;

        // Parse "encoding;q=X.X"
        float q = 1.0f;
        auto semi = token.find(';');
        auto name = token.substr(0, semi);

        // Trim whitespace from name
        while (!name.empty() && name.back() == ' ') name.remove_suffix(1);
        while (!name.empty() && name.front() == ' ') name.remove_prefix(1);

        if (semi != std::string_view::npos) {
            auto qpart = token.substr(semi + 1);
            auto eq = qpart.find('=');
            if (eq != std::string_view::npos) {
                auto val = qpart.substr(eq + 1);
                while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
                try {
                    q = std::stof(std::string(val));
                } catch (...) {
                    q = 1.0f;
                }
            }
        }

        if (q <= 0.0f) continue;

        if (name == "zstd") supported.push_back({CompressionAlgo::ZSTD, q});
        else if (name == "br") supported.push_back({CompressionAlgo::BROTLI, q});
        else if (name == "gzip") supported.push_back({CompressionAlgo::GZIP, q});
    }

    if (supported.empty()) return CompressionAlgo::NONE;

    // Sort by quality descending, then by our preference (zstd > br > gzip)
    std::sort(supported.begin(), supported.end(), [](const Encoding& a, const Encoding& b) {
        if (a.quality != b.quality) return a.quality > b.quality;
        return static_cast<int>(a.algo) < static_cast<int>(b.algo);
    });

    return supported[0].algo;
}

// === Brotli ===

std::string Compressor::brotli_compress(std::string_view input, int quality) {
    if (quality < 0) quality = BROTLI_FAST_QUALITY;

    size_t max_size = BrotliEncoderMaxCompressedSize(input.size());
    std::string output(max_size, '\0');

    size_t encoded_size = max_size;
    if (!BrotliEncoderCompress(
            quality, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC,
            input.size(), reinterpret_cast<const uint8_t*>(input.data()),
            &encoded_size, reinterpret_cast<uint8_t*>(output.data()))) {
        LOG_WARN("Brotli compression failed");
        return std::string(input);
    }

    output.resize(encoded_size);
    return output;
}

std::optional<std::string> Compressor::brotli_decompress(std::string_view input) {
    // Start with 4x input size estimate
    std::string output;
    output.resize(input.size() * 4);

    BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!state) return std::nullopt;

    size_t available_in = input.size();
    const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input.data());
    size_t total_out = 0;

    BrotliDecoderResult result;
    do {
        size_t available_out = output.size() - total_out;
        uint8_t* next_out = reinterpret_cast<uint8_t*>(output.data()) + total_out;

        result = BrotliDecoderDecompressStream(
            state, &available_in, &next_in, &available_out, &next_out, &total_out);

        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            output.resize(output.size() * 2);
        }
    } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

    BrotliDecoderDestroyInstance(state);

    if (result != BROTLI_DECODER_RESULT_SUCCESS) return std::nullopt;

    output.resize(total_out);
    return output;
}

// === Zstd ===

std::string Compressor::zstd_compress(std::string_view input, int level) {
    if (level < 0) level = ZSTD_FAST_LEVEL;

    size_t max_size = ZSTD_compressBound(input.size());
    std::string output(max_size, '\0');

    size_t compressed_size = ZSTD_compress(
        output.data(), max_size,
        input.data(), input.size(),
        level);

    if (ZSTD_isError(compressed_size)) {
        LOG_WARN("Zstd compression failed: " + std::string(ZSTD_getErrorName(compressed_size)));
        return std::string(input);
    }

    output.resize(compressed_size);
    return output;
}

std::optional<std::string> Compressor::zstd_decompress(std::string_view input) {
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(input.data(), input.size());

    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        // Streaming decompression needed
        decompressed_size = input.size() * 4;
    } else if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        return std::nullopt;
    }

    std::string output(static_cast<size_t>(decompressed_size), '\0');

    size_t result = ZSTD_decompress(
        output.data(), output.size(),
        input.data(), input.size());

    if (ZSTD_isError(result)) return std::nullopt;

    output.resize(result);
    return output;
}

// === Generic interface ===

std::string Compressor::compress(std::string_view input, CompressionAlgo algo, int quality) {
    switch (algo) {
        case CompressionAlgo::BROTLI: return brotli_compress(input, quality);
        case CompressionAlgo::ZSTD:   return zstd_compress(input, quality);
        case CompressionAlgo::GZIP:
            // TODO: Implement gzip as legacy fallback
            return std::string(input);
        default: return std::string(input);
    }
}

std::optional<std::string> Compressor::decompress(std::string_view input, CompressionAlgo algo) {
    switch (algo) {
        case CompressionAlgo::BROTLI: return brotli_decompress(input);
        case CompressionAlgo::ZSTD:   return zstd_decompress(input);
        default: return std::string(input);
    }
}

// === Streaming compressor ===

StreamingCompressor::StreamingCompressor(CompressionAlgo algo, int quality) : algo_(algo) {
    switch (algo_) {
        case CompressionAlgo::BROTLI: {
            auto* state = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
            if (state) {
                int q = (quality < 0) ? Compressor::BROTLI_FAST_QUALITY : quality;
                BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, static_cast<uint32_t>(q));
                ctx_ = state;
            }
            break;
        }
        case CompressionAlgo::ZSTD: {
            auto* cctx = ZSTD_createCCtx();
            if (cctx) {
                int lvl = (quality < 0) ? Compressor::ZSTD_FAST_LEVEL : quality;
                ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, lvl);
                ctx_ = cctx;
            }
            break;
        }
        default: break;
    }
}

StreamingCompressor::~StreamingCompressor() {
    switch (algo_) {
        case CompressionAlgo::BROTLI:
            if (ctx_) BrotliEncoderDestroyInstance(static_cast<BrotliEncoderState*>(ctx_));
            break;
        case CompressionAlgo::ZSTD:
            if (ctx_) ZSTD_freeCCtx(static_cast<ZSTD_CCtx*>(ctx_));
            break;
        default: break;
    }
}

std::string StreamingCompressor::feed(std::string_view input) {
    if (!ctx_ || input.empty()) return {};

    std::string output;

    switch (algo_) {
        case CompressionAlgo::BROTLI: {
            auto* state = static_cast<BrotliEncoderState*>(ctx_);
            size_t available_in = input.size();
            const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input.data());

            while (available_in > 0) {
                uint8_t buf[8192];
                size_t available_out = sizeof(buf);
                uint8_t* next_out = buf;

                BrotliEncoderCompressStream(
                    state, BROTLI_OPERATION_PROCESS,
                    &available_in, &next_in, &available_out, &next_out, nullptr);

                size_t produced = sizeof(buf) - available_out;
                output.append(reinterpret_cast<char*>(buf), produced);
            }
            break;
        }
        case CompressionAlgo::ZSTD: {
            auto* cctx = static_cast<ZSTD_CCtx*>(ctx_);
            ZSTD_inBuffer in_buf = {input.data(), input.size(), 0};

            while (in_buf.pos < in_buf.size) {
                uint8_t buf[8192];
                ZSTD_outBuffer out_buf = {buf, sizeof(buf), 0};
                ZSTD_compressStream2(cctx, &out_buf, &in_buf, ZSTD_e_continue);
                output.append(reinterpret_cast<char*>(buf), out_buf.pos);
            }
            break;
        }
        default: return std::string(input);
    }

    return output;
}

std::string StreamingCompressor::finish() {
    if (!ctx_) return {};

    std::string output;

    switch (algo_) {
        case CompressionAlgo::BROTLI: {
            auto* state = static_cast<BrotliEncoderState*>(ctx_);
            size_t available_in = 0;
            const uint8_t* next_in = nullptr;

            while (!BrotliEncoderIsFinished(state)) {
                uint8_t buf[8192];
                size_t available_out = sizeof(buf);
                uint8_t* next_out = buf;

                BrotliEncoderCompressStream(
                    state, BROTLI_OPERATION_FINISH,
                    &available_in, &next_in, &available_out, &next_out, nullptr);

                size_t produced = sizeof(buf) - available_out;
                output.append(reinterpret_cast<char*>(buf), produced);
            }
            break;
        }
        case CompressionAlgo::ZSTD: {
            auto* cctx = static_cast<ZSTD_CCtx*>(ctx_);
            ZSTD_inBuffer in_buf = {nullptr, 0, 0};

            size_t remaining;
            do {
                uint8_t buf[8192];
                ZSTD_outBuffer out_buf = {buf, sizeof(buf), 0};
                remaining = ZSTD_compressStream2(cctx, &out_buf, &in_buf, ZSTD_e_end);
                output.append(reinterpret_cast<char*>(buf), out_buf.pos);
            } while (remaining > 0);
            break;
        }
        default: break;
    }

    return output;
}

} // namespace js
