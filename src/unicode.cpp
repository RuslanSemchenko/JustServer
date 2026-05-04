#include "unicode.hpp"
#include <algorithm>
#include <cstring>

namespace js {

int Unicode::decode_codepoint(const char* data, size_t len, uint32_t& codepoint) {
    if (len == 0) return 0;

    auto byte = static_cast<uint8_t>(data[0]);

    // Single byte (ASCII)
    if (byte < 0x80) {
        codepoint = byte;
        return 1;
    }

    int bytes_expected;
    uint32_t cp;

    if ((byte & 0xE0) == 0xC0) {
        bytes_expected = 2;
        cp = byte & 0x1F;
    } else if ((byte & 0xF0) == 0xE0) {
        bytes_expected = 3;
        cp = byte & 0x0F;
    } else if ((byte & 0xF8) == 0xF0) {
        bytes_expected = 4;
        cp = byte & 0x07;
    } else {
        // Invalid leading byte
        return 0;
    }

    if (static_cast<int>(len) < bytes_expected) return 0;

    for (int i = 1; i < bytes_expected; ++i) {
        auto cont = static_cast<uint8_t>(data[i]);
        if ((cont & 0xC0) != 0x80) return 0; // Invalid continuation byte
        cp = (cp << 6) | (cont & 0x3F);
    }

    codepoint = cp;
    return bytes_expected;
}

bool Unicode::is_overlong(uint32_t codepoint, int bytes_used) {
    switch (bytes_used) {
        case 2: return codepoint < 0x80;
        case 3: return codepoint < 0x800;
        case 4: return codepoint < 0x10000;
        default: return false;
    }
}

bool Unicode::is_dangerous_codepoint(uint32_t codepoint) {
    // Null character
    if (codepoint == 0) return true;

    // Surrogates (should never appear in UTF-8)
    if (codepoint >= 0xD800 && codepoint <= 0xDFFF) return true;

    // Non-characters
    if (codepoint >= 0xFDD0 && codepoint <= 0xFDEF) return true;
    if ((codepoint & 0xFFFE) == 0xFFFE) return true; // U+xFFFE and U+xFFFF

    // BOM and similar
    if (codepoint == 0xFEFF) return true; // BOM in middle of string

    // Right-to-left override and similar BiDi controls (used in path spoofing)
    if (codepoint == 0x202A || codepoint == 0x202B || // LRE, RLE
        codepoint == 0x202C || codepoint == 0x202D || // PDF, LRO
        codepoint == 0x202E ||                         // RLO
        codepoint == 0x2066 || codepoint == 0x2067 || // LRI, RLI
        codepoint == 0x2068 || codepoint == 0x2069) { // FSI, PDI
        return true;
    }

    // Homograph attack characters (Cyrillic lookalikes, etc.)
    // These are commonly used in IDN homograph attacks

    // Zero-width characters (used to bypass filters)
    if (codepoint == 0x200B || // Zero Width Space
        codepoint == 0x200C || // Zero Width Non-Joiner
        codepoint == 0x200D || // Zero Width Joiner
        codepoint == 0xFEFF) { // Zero Width No-Break Space
        return true;
    }

    return false;
}

bool Unicode::is_valid_utf8(std::string_view data) {
    size_t i = 0;
    while (i < data.size()) {
        uint32_t cp;
        int bytes = decode_codepoint(data.data() + i, data.size() - i, cp);
        if (bytes == 0) return false;

        // Check for overlong encodings
        if (is_overlong(cp, bytes)) return false;

        // Check for surrogates in UTF-8
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;

        // Check valid range
        if (cp > 0x10FFFF) return false;

        i += static_cast<size_t>(bytes);
    }
    return true;
}

std::string Unicode::normalize_utf8(std::string_view input) {
    std::string result;
    result.reserve(input.size());

    size_t i = 0;
    while (i < input.size()) {
        uint32_t cp;
        int bytes = decode_codepoint(input.data() + i, input.size() - i, cp);

        if (bytes == 0) {
            // Skip invalid byte
            i++;
            continue;
        }

        // Skip dangerous codepoints
        if (is_dangerous_codepoint(cp)) {
            i += static_cast<size_t>(bytes);
            continue;
        }

        // Skip overlong encodings - re-encode properly
        if (is_overlong(cp, bytes)) {
            // Re-encode with minimum bytes
            if (cp < 0x80) {
                result += static_cast<char>(cp);
            } else if (cp < 0x800) {
                result += static_cast<char>(0xC0 | (cp >> 6));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                result += static_cast<char>(0xE0 | (cp >> 12));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                result += static_cast<char>(0xF0 | (cp >> 18));
                result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            }
        } else {
            // Copy as-is
            result.append(input.data() + i, static_cast<size_t>(bytes));
        }

        i += static_cast<size_t>(bytes);
    }

    return result;
}

bool Unicode::detect_multibyte_bypass(std::string_view data) {
    size_t i = 0;
    while (i < data.size()) {
        uint32_t cp;
        int bytes = decode_codepoint(data.data() + i, data.size() - i, cp);

        if (bytes == 0) {
            // Invalid UTF-8 sequence - suspicious
            return true;
        }

        // Overlong encoding - attack vector
        if (is_overlong(cp, bytes)) {
            return true;
        }

        // Dangerous codepoints
        if (is_dangerous_codepoint(cp)) {
            return true;
        }

        // Check for fullwidth characters that map to ASCII
        // Fullwidth Latin (FF01-FF5E maps to 0021-007E)
        if (cp >= 0xFF01 && cp <= 0xFF5E) {
            // These could be used to bypass ASCII-based filters
            // e.g., fullwidth "/" (U+FF0F) to bypass path traversal checks
            uint32_t ascii_equiv = cp - 0xFF01 + 0x21;
            if (ascii_equiv == '/' || ascii_equiv == '\\' ||
                ascii_equiv == '.' || ascii_equiv == '<' ||
                ascii_equiv == '>' || ascii_equiv == '\'' ||
                ascii_equiv == '"' || ascii_equiv == '&') {
                return true;
            }
        }

        // Half-width Katakana variations (used in Japanese encoding attacks)
        if (cp >= 0xFF65 && cp <= 0xFF9F) {
            // Not inherently dangerous, but flag if mixed with Latin
        }

        i += static_cast<size_t>(bytes);
    }

    return false;
}

bool Unicode::has_overlong_encoding(std::string_view data) {
    size_t i = 0;
    while (i < data.size()) {
        uint32_t cp;
        int bytes = decode_codepoint(data.data() + i, data.size() - i, cp);

        if (bytes == 0) {
            i++;
            continue;
        }

        if (is_overlong(cp, bytes)) return true;

        i += static_cast<size_t>(bytes);
    }
    return false;
}

bool Unicode::detect_shiftjis_bypass(std::string_view data) {
    // Detect Shift-JIS byte sequences that could interfere with ASCII parsing
    // In Shift-JIS, lead bytes 0x81-0x9F and 0xE0-0xEF are followed by
    // trail bytes 0x40-0x7E and 0x80-0xFC
    // The trail byte range 0x40-0x7E overlaps with ASCII, which can be exploited

    for (size_t i = 0; i < data.size(); ++i) {
        auto byte = static_cast<uint8_t>(data[i]);

        // Shift-JIS lead byte ranges
        if ((byte >= 0x81 && byte <= 0x9F) || (byte >= 0xE0 && byte <= 0xEF)) {
            if (i + 1 < data.size()) {
                auto trail = static_cast<uint8_t>(data[i + 1]);

                // If trail byte happens to be an ASCII metacharacter
                // this could be used to bypass security checks
                if (trail == '/' || trail == '\\' || trail == '.' ||
                    trail == '<' || trail == '>' || trail == '\'' ||
                    trail == '"' || trail == '&' || trail == '|' ||
                    trail == ';' || trail == '`') {
                    return true;
                }
            }
        }
    }

    return false;
}

std::string Unicode::decode_percent_utf8(std::string_view input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            char hex[3] = {input[i + 1], input[i + 2], '\0'};
            char* end = nullptr;
            auto val = std::strtol(hex, &end, 16);
            if (end == hex + 2) {
                result += static_cast<char>(val);
                i += 2;
                continue;
            }
        }
        result += input[i];
    }

    return result;
}

} // namespace js
