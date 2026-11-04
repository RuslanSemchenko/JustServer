#include "compression.hpp"
#include "logger.hpp"

#include <brotli/encode.h>
#include <brotli/decode.h>
#include <zstd.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <climits>
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
        else if (name == "gzip" || name == "x-gzip") supported.push_back({CompressionAlgo::GZIP, q});
        else if (name == "*") {
            // Wildcard: any encoding is acceptable, offer all of ours at this quality
            supported.push_back({CompressionAlgo::ZSTD, q});
            supported.push_back({CompressionAlgo::BROTLI, q});
            supported.push_back({CompressionAlgo::GZIP, q});
        }
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

std::optional<std::string> Compressor::brotli_decompress(std::string_view input, size_t max_output) {
    // Start with 4x input size estimate (bounded by the output limit)
    std::string output;
    output.resize(std::min(std::max<size_t>(input.size() * 4, 1024), std::max<size_t>(max_output, 1)));

    BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!state) return std::nullopt;

    size_t available_in = input.size();
    const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input.data());
    size_t total_out = 0;
    bool too_large = false;

    BrotliDecoderResult result;
    do {
        size_t available_out = output.size() - total_out;
        uint8_t* next_out = reinterpret_cast<uint8_t*>(output.data()) + total_out;

        result = BrotliDecoderDecompressStream(
            state, &available_in, &next_in, &available_out, &next_out, &total_out);

        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            if (output.size() >= max_output) {
                too_large = true;
                break;
            }
            output.resize(std::min(output.size() * 2, max_output));
        }
    } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

    BrotliDecoderDestroyInstance(state);

    if (too_large) {
        LOG_WARN("Brotli decompression aborted: output exceeds limit");
        return std::nullopt;
    }
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

std::optional<std::string> Compressor::zstd_decompress(std::string_view input, size_t max_output) {
    unsigned long long content_size = ZSTD_getFrameContentSize(input.data(), input.size());
    if (content_size == ZSTD_CONTENTSIZE_ERROR) return std::nullopt;

    // Fast path: single frame with a known (and acceptable) content size
    if (content_size != ZSTD_CONTENTSIZE_UNKNOWN) {
        if (content_size > max_output) {
            LOG_WARN("Zstd decompression rejected: declared size exceeds limit");
            return std::nullopt;
        }
        std::string output(static_cast<size_t>(content_size), '\0');
        size_t result = ZSTD_decompress(output.data(), output.size(), input.data(), input.size());
        if (!ZSTD_isError(result)) {
            output.resize(result);
            return output;
        }
        // Fall through to streaming (e.g. multiple concatenated frames)
    }

    // Streaming path: unknown content size (streaming compressor output) or multi-frame input
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) return std::nullopt;

    std::string output;
    ZSTD_inBuffer in_buf = {input.data(), input.size(), 0};
    std::array<char, 16384> buf{};
    size_t last_ret = 0;

    while (in_buf.pos < in_buf.size) {
        ZSTD_outBuffer out_buf = {buf.data(), buf.size(), 0};
        last_ret = ZSTD_decompressStream(dctx, &out_buf, &in_buf);
        if (ZSTD_isError(last_ret)) {
            ZSTD_freeDCtx(dctx);
            return std::nullopt;
        }
        if (output.size() + out_buf.pos > max_output) {
            ZSTD_freeDCtx(dctx);
            LOG_WARN("Zstd decompression aborted: output exceeds limit");
            return std::nullopt;
        }
        output.append(buf.data(), out_buf.pos);
    }

    // Drain any output still buffered inside the decoder
    while (last_ret != 0) {
        ZSTD_outBuffer out_buf = {buf.data(), buf.size(), 0};
        last_ret = ZSTD_decompressStream(dctx, &out_buf, &in_buf);
        if (ZSTD_isError(last_ret) || out_buf.pos == 0) break;
        if (output.size() + out_buf.pos > max_output) {
            ZSTD_freeDCtx(dctx);
            return std::nullopt;
        }
        output.append(buf.data(), out_buf.pos);
    }

    ZSTD_freeDCtx(dctx);

    // last_ret != 0 means the final frame is truncated
    if (last_ret != 0) return std::nullopt;
    return output;
}

// === Gzip (zlib) ===

std::string Compressor::gzip_compress(std::string_view input, int level) {
    if (level < 0 || level > 9) level = GZIP_DEFAULT_LEVEL;

    z_stream zs{};
    // windowBits 15 + 16 => gzip wrapper (RFC 1952) instead of raw zlib
    if (deflateInit2(&zs, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        LOG_WARN("Gzip compression init failed");
        return std::string(input);
    }

    std::string output;
    output.resize(deflateBound(&zs, static_cast<uLong>(input.size())) + 32);

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    zs.next_out = reinterpret_cast<Bytef*>(output.data());

    // zlib counters are 32-bit: feed huge inputs in slices
    size_t remaining_in = input.size();
    int ret = Z_OK;
    while (ret == Z_OK) {
        uInt in_chunk = static_cast<uInt>(std::min<size_t>(remaining_in, UINT_MAX));
        zs.avail_in = in_chunk;
        size_t out_left = output.size() - static_cast<size_t>(
            reinterpret_cast<char*>(zs.next_out) - output.data());
        zs.avail_out = static_cast<uInt>(std::min<size_t>(out_left, UINT_MAX));

        bool last = (in_chunk == remaining_in);
        ret = deflate(&zs, last ? Z_FINISH : Z_NO_FLUSH);
        remaining_in -= in_chunk - zs.avail_in;
        if (ret == Z_OK && zs.avail_out == 0) {
            size_t used = static_cast<size_t>(reinterpret_cast<char*>(zs.next_out) - output.data());
            output.resize(output.size() * 2);
            zs.next_out = reinterpret_cast<Bytef*>(output.data()) + used;
        }
    }

    size_t produced = static_cast<size_t>(reinterpret_cast<char*>(zs.next_out) - output.data());
    deflateEnd(&zs);

    if (ret != Z_STREAM_END) {
        LOG_WARN("Gzip compression failed");
        return std::string(input);
    }

    output.resize(produced);
    return output;
}

std::optional<std::string> Compressor::gzip_decompress(std::string_view input, size_t max_output) {
    z_stream zs{};
    // windowBits 15 + 32 => auto-detect gzip or zlib header
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return std::nullopt;

    std::string output;
    std::array<char, 16384> buf{};

    size_t consumed = 0;
    int ret = Z_OK;
    while (true) {
        if (zs.avail_in == 0 && consumed < input.size()) {
            uInt in_chunk = static_cast<uInt>(std::min<size_t>(input.size() - consumed, UINT_MAX));
            zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data() + consumed));
            zs.avail_in = in_chunk;
            consumed += in_chunk;
        }

        zs.next_out = reinterpret_cast<Bytef*>(buf.data());
        zs.avail_out = static_cast<uInt>(buf.size());

        ret = inflate(&zs, Z_NO_FLUSH);
        size_t produced = buf.size() - zs.avail_out;

        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) break;
        if (output.size() + produced > max_output) {
            inflateEnd(&zs);
            LOG_WARN("Gzip decompression aborted: output exceeds limit");
            return std::nullopt;
        }
        output.append(buf.data(), produced);

        if (ret == Z_STREAM_END) {
            // Support concatenated gzip members (RFC 1952 section 2.2)
            if (zs.avail_in == 0 && consumed >= input.size()) break;
            if (inflateReset(&zs) != Z_OK) break;
            continue;
        }
        if (ret == Z_BUF_ERROR && zs.avail_in == 0 && consumed >= input.size()) break; // Truncated
    }

    inflateEnd(&zs);
    if (ret != Z_STREAM_END) return std::nullopt;
    return output;
}

// === Generic interface ===

std::string Compressor::compress(std::string_view input, CompressionAlgo algo, int quality) {
    switch (algo) {
        case CompressionAlgo::BROTLI: return brotli_compress(input, quality);
        case CompressionAlgo::ZSTD:   return zstd_compress(input, quality);
        case CompressionAlgo::GZIP:   return gzip_compress(input, quality);
        default: return std::string(input);
    }
}

std::optional<std::string> Compressor::decompress(std::string_view input, CompressionAlgo algo,
                                                  size_t max_output) {
    switch (algo) {
        case CompressionAlgo::BROTLI: return brotli_decompress(input, max_output);
        case CompressionAlgo::ZSTD:   return zstd_decompress(input, max_output);
        case CompressionAlgo::GZIP:   return gzip_decompress(input, max_output);
        default:
            if (input.size() > max_output) return std::nullopt;
            return std::string(input);
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
        case CompressionAlgo::GZIP: {
            auto* zs = new z_stream{};
            int lvl = (quality < 0 || quality > 9) ? Compressor::GZIP_DEFAULT_LEVEL : quality;
            if (deflateInit2(zs, lvl, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
                ctx_ = zs;
            } else {
                delete zs;
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
        case CompressionAlgo::GZIP:
            if (ctx_) {
                auto* zs = static_cast<z_stream*>(ctx_);
                deflateEnd(zs);
                delete zs;
            }
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
                size_t ret = ZSTD_compressStream2(cctx, &out_buf, &in_buf, ZSTD_e_continue);
                if (ZSTD_isError(ret)) break;
                output.append(reinterpret_cast<char*>(buf), out_buf.pos);
            }
            break;
        }
        case CompressionAlgo::GZIP: {
            auto* zs = static_cast<z_stream*>(ctx_);
            size_t offset = 0;
            while (offset < input.size()) {
                uInt in_chunk = static_cast<uInt>(std::min<size_t>(input.size() - offset, UINT_MAX));
                zs->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data() + offset));
                zs->avail_in = in_chunk;
                do {
                    uint8_t buf[8192];
                    zs->next_out = buf;
                    zs->avail_out = sizeof(buf);
                    if (deflate(zs, Z_NO_FLUSH) == Z_STREAM_ERROR) return output;
                    output.append(reinterpret_cast<char*>(buf), sizeof(buf) - zs->avail_out);
                } while (zs->avail_out == 0);
                offset += in_chunk;
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
                if (ZSTD_isError(remaining)) break;
                output.append(reinterpret_cast<char*>(buf), out_buf.pos);
            } while (remaining > 0);
            break;
        }
        case CompressionAlgo::GZIP: {
            auto* zs = static_cast<z_stream*>(ctx_);
            zs->next_in = nullptr;
            zs->avail_in = 0;
            int ret;
            do {
                uint8_t buf[8192];
                zs->next_out = buf;
                zs->avail_out = sizeof(buf);
                ret = deflate(zs, Z_FINISH);
                if (ret == Z_STREAM_ERROR) break;
                output.append(reinterpret_cast<char*>(buf), sizeof(buf) - zs->avail_out);
            } while (ret != Z_STREAM_END);
            break;
        }
        default: break;
    }

    return output;
}

} // namespace js
