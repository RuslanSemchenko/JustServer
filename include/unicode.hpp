#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <cstdint>

namespace js {

class Unicode {
public:
    // Validate that a string is valid UTF-8
    static bool is_valid_utf8(std::string_view data);

    // Normalize UTF-8 string (NFC normalization - basic)
    static std::string normalize_utf8(std::string_view input);

    // Detect multi-byte bypass attempts
    // Returns true if suspicious encoding is detected
    static bool detect_multibyte_bypass(std::string_view data);

    // Detect overlong UTF-8 encodings (attack vector)
    static bool has_overlong_encoding(std::string_view data);

    // Detect Shift-JIS mixed encoding attacks
    static bool detect_shiftjis_bypass(std::string_view data);

    // Decode percent-encoded UTF-8 sequences
    static std::string decode_percent_utf8(std::string_view input);

private:
    // Decode a single UTF-8 codepoint, returns bytes consumed (0 on error)
    static int decode_codepoint(const char* data, size_t len, uint32_t& codepoint);

    // Check if codepoint uses minimum bytes (overlong check)
    static bool is_overlong(uint32_t codepoint, int bytes_used);

    // Check if codepoint is in dangerous ranges
    static bool is_dangerous_codepoint(uint32_t codepoint);
};

} // namespace js
