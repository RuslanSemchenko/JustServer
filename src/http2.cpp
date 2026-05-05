#include "http2.hpp"
#include "logger.hpp"
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <array>

namespace js {

// ===== HPACK Huffman Decoding Table (RFC 7541, Appendix B) =====
// Each entry: {code, bit_length}
// Index = symbol value (0-256, where 256 = EOS)
struct HuffmanEntry {
    uint32_t code;
    uint8_t bits;
};

static constexpr std::array<HuffmanEntry, 257> HUFFMAN_TABLE = {{
    {0x1ff8, 13},     // 0
    {0x7fffd8, 23},   // 1
    {0xfffffe2, 28},  // 2
    {0xfffffe3, 28},  // 3
    {0xfffffe4, 28},  // 4
    {0xfffffe5, 28},  // 5
    {0xfffffe6, 28},  // 6
    {0xfffffe7, 28},  // 7
    {0xfffffe8, 28},  // 8
    {0xffffea, 24},   // 9
    {0x3ffffffc, 30}, // 10
    {0xfffffe9, 28},  // 11
    {0xfffffea, 28},  // 12
    {0x3ffffffd, 30}, // 13
    {0xfffffeb, 28},  // 14
    {0xfffffec, 28},  // 15
    {0xfffffed, 28},  // 16
    {0xfffffee, 28},  // 17
    {0xfffffef, 28},  // 18
    {0xffffff0, 28},  // 19
    {0xffffff1, 28},  // 20
    {0xffffff2, 28},  // 21
    {0x3ffffffe, 30}, // 22
    {0xffffff3, 28},  // 23
    {0xffffff4, 28},  // 24
    {0xffffff5, 28},  // 25
    {0xffffff6, 28},  // 26
    {0xffffff7, 28},  // 27
    {0xffffff8, 28},  // 28
    {0xffffff9, 28},  // 29
    {0xffffffa, 28},  // 30
    {0xffffffb, 28},  // 31
    {0x14, 6},        // 32 ' '
    {0x3f8, 10},      // 33 '!'
    {0x3f9, 10},      // 34 '"'
    {0xffa, 12},      // 35 '#'
    {0x1ff9, 13},     // 36 '$'
    {0x15, 6},        // 37 '%'
    {0xf8, 8},        // 38 '&'
    {0x7fa, 11},      // 39 '\''
    {0x3fa, 10},      // 40 '('
    {0x3fb, 10},      // 41 ')'
    {0xf9, 8},        // 42 '*'
    {0x7fb, 11},      // 43 '+'
    {0xfa, 8},        // 44 ','
    {0x16, 6},        // 45 '-'
    {0x17, 6},        // 46 '.'
    {0x18, 6},        // 47 '/'
    {0x0, 5},         // 48 '0'
    {0x1, 5},         // 49 '1'
    {0x2, 5},         // 50 '2'
    {0x19, 6},        // 51 '3'
    {0x1a, 6},        // 52 '4'
    {0x1b, 6},        // 53 '5'
    {0x1c, 6},        // 54 '6'
    {0x1d, 6},        // 55 '7'
    {0x1e, 6},        // 56 '8'
    {0x1f, 6},        // 57 '9'
    {0x5c, 7},        // 58 ':'
    {0xfb, 8},        // 59 ';'
    {0x7ffc, 15},     // 60 '<'
    {0x20, 6},        // 61 '='
    {0xffb, 12},      // 62 '>'
    {0x3fc, 10},      // 63 '?'
    {0x1ffa, 13},     // 64 '@'
    {0x21, 6},        // 65 'A'
    {0x5d, 7},        // 66 'B'
    {0x5e, 7},        // 67 'C'
    {0x5f, 7},        // 68 'D'
    {0x60, 7},        // 69 'E'
    {0x61, 7},        // 70 'F'
    {0x62, 7},        // 71 'G'
    {0x63, 7},        // 72 'H'
    {0x64, 7},        // 73 'I'
    {0x65, 7},        // 74 'J'
    {0x66, 7},        // 75 'K'
    {0x67, 7},        // 76 'L'
    {0x68, 7},        // 77 'M'
    {0x69, 7},        // 78 'N'
    {0x6a, 7},        // 79 'O'
    {0x6b, 7},        // 80 'P'
    {0x6c, 7},        // 81 'Q'
    {0x6d, 7},        // 82 'R'
    {0x6e, 7},        // 83 'S'
    {0x6f, 7},        // 84 'T'
    {0x70, 7},        // 85 'U'
    {0x71, 7},        // 86 'V'
    {0x72, 7},        // 87 'W'
    {0xfc, 8},        // 88 'X'
    {0x73, 7},        // 89 'Y'
    {0xfd, 8},        // 90 'Z'
    {0x1ffb, 13},     // 91 '['
    {0x7fff0, 19},    // 92 '\\'
    {0x1ffc, 13},     // 93 ']'
    {0x3ffc, 14},     // 94 '^'
    {0x22, 6},        // 95 '_'
    {0x7ffd, 15},     // 96 '`'
    {0x3, 5},         // 97 'a'
    {0x23, 6},        // 98 'b'
    {0x4, 5},         // 99 'c'
    {0x24, 6},        // 100 'd'
    {0x5, 5},         // 101 'e'
    {0x25, 6},        // 102 'f'
    {0x26, 6},        // 103 'g'
    {0x27, 6},        // 104 'h'
    {0x6, 5},         // 105 'i'
    {0x74, 7},        // 106 'j'
    {0x75, 7},        // 107 'k'
    {0x28, 6},        // 108 'l'
    {0x29, 6},        // 109 'm'
    {0x2a, 6},        // 110 'n'
    {0x7, 5},         // 111 'o'
    {0x2b, 6},        // 112 'p'
    {0x76, 7},        // 113 'q'
    {0x2c, 6},        // 114 'r'
    {0x8, 5},         // 115 's'
    {0x9, 5},         // 116 't'
    {0x2d, 6},        // 117 'u'
    {0x77, 7},        // 118 'v'
    {0x78, 7},        // 119 'w'
    {0x79, 7},        // 120 'x'
    {0x7a, 7},        // 121 'y'
    {0x7b, 7},        // 122 'z'
    {0x7fffe, 19},    // 123 '{'
    {0x7fc, 11},      // 124 '|'
    {0x3ffd, 14},     // 125 '}'
    {0x1ffd, 13},     // 126 '~'
    {0xffffffc, 28},  // 127
    {0xfffe6, 20},    // 128
    {0x3fffd2, 22},   // 129
    {0xfffe7, 20},    // 130
    {0xfffe8, 20},    // 131
    {0x3fffd3, 22},   // 132
    {0x3fffd4, 22},   // 133
    {0x3fffd5, 22},   // 134
    {0x7fffd9, 23},   // 135
    {0x3fffd6, 22},   // 136
    {0x7fffda, 23},   // 137
    {0x7fffdb, 23},   // 138
    {0x7fffdc, 23},   // 139
    {0x7fffdd, 23},   // 140
    {0x7fffde, 23},   // 141
    {0xffffeb, 24},   // 142
    {0x7fffdf, 23},   // 143
    {0xffffec, 24},   // 144
    {0xffffed, 24},   // 145
    {0x3fffd7, 22},   // 146
    {0x7fffe0, 23},   // 147
    {0xffffee, 24},   // 148
    {0x7fffe1, 23},   // 149
    {0x7fffe2, 23},   // 150
    {0x7fffe3, 23},   // 151
    {0x7fffe4, 23},   // 152
    {0x1fffdc, 21},   // 153
    {0x3fffd8, 22},   // 154
    {0x7fffe5, 23},   // 155
    {0x3fffd9, 22},   // 156
    {0x7fffe6, 23},   // 157
    {0x7fffe7, 23},   // 158
    {0xffffef, 24},   // 159
    {0x3fffda, 22},   // 160
    {0x1fffdd, 21},   // 161
    {0xfffe9, 20},    // 162
    {0x3fffdb, 22},   // 163
    {0x3fffdc, 22},   // 164
    {0x7fffe8, 23},   // 165
    {0x7fffe9, 23},   // 166
    {0x1fffde, 21},   // 167
    {0x7fffea, 23},   // 168
    {0x3fffdd, 22},   // 169
    {0x3fffde, 22},   // 170
    {0xfffff0, 24},   // 171
    {0x1fffdf, 21},   // 172
    {0x3fffdf, 22},   // 173
    {0x7fffeb, 23},   // 174
    {0x7fffec, 23},   // 175
    {0x1fffe0, 21},   // 176
    {0x1fffe1, 21},   // 177
    {0x3fffe0, 22},   // 178
    {0x1fffe2, 21},   // 179
    {0x7fffed, 23},   // 180
    {0x3fffe1, 22},   // 181
    {0x7fffee, 23},   // 182
    {0x7fffef, 23},   // 183
    {0xfffea, 20},    // 184
    {0x3fffe2, 22},   // 185
    {0x3fffe3, 22},   // 186
    {0x3fffe4, 22},   // 187
    {0x7ffff0, 23},   // 188
    {0x3fffe5, 22},   // 189
    {0x3fffe6, 22},   // 190
    {0x7ffff1, 23},   // 191
    {0x3ffffe0, 26},  // 192
    {0x3ffffe1, 26},  // 193
    {0xfffeb, 20},    // 194
    {0x7fff1, 19},    // 195
    {0x3fffe7, 22},   // 196
    {0x7ffff2, 23},   // 197
    {0x3fffe8, 22},   // 198
    {0x1ffffec, 25},  // 199
    {0x3ffffe2, 26},  // 200
    {0x3ffffe3, 26},  // 201
    {0x3ffffe4, 26},  // 202
    {0x7ffffde, 27},  // 203
    {0x7ffffdf, 27},  // 204
    {0x3ffffe5, 26},  // 205
    {0xfffff1, 24},   // 206
    {0x1ffffed, 25},  // 207
    {0x7fff2, 19},    // 208
    {0x1fffe3, 21},   // 209
    {0x3ffffe6, 26},  // 210
    {0x7ffffe0, 27},  // 211
    {0x7ffffe1, 27},  // 212
    {0x3ffffe7, 26},  // 213
    {0x7ffffe2, 27},  // 214
    {0xfffff2, 24},   // 215
    {0x1fffe4, 21},   // 216
    {0x1fffe5, 21},   // 217
    {0x3ffffe8, 26},  // 218
    {0x3ffffe9, 26},  // 219
    {0xffffffd, 28},  // 220
    {0x7ffffe3, 27},  // 221
    {0x7ffffe4, 27},  // 222
    {0x7ffffe5, 27},  // 223
    {0xfffec, 20},    // 224
    {0xfffff3, 24},   // 225
    {0xfffed, 20},    // 226
    {0x1fffe6, 21},   // 227
    {0x3fffe9, 22},   // 228
    {0x1fffe7, 21},   // 229
    {0x1fffe8, 21},   // 230
    {0x7ffff3, 23},   // 231
    {0x3fffea, 22},   // 232
    {0x3fffeb, 22},   // 233
    {0x1ffffee, 25},  // 234
    {0x1ffffef, 25},  // 235
    {0xfffff4, 24},   // 236
    {0xfffff5, 24},   // 237
    {0x3ffffea, 26},  // 238
    {0x7ffff4, 23},   // 239
    {0x3ffffeb, 26},  // 240
    {0x7ffffe6, 27},  // 241
    {0x3ffffec, 26},  // 242
    {0x3ffffed, 26},  // 243
    {0x7ffffe7, 27},  // 244
    {0x7ffffe8, 27},  // 245
    {0x7ffffe9, 27},  // 246
    {0x7ffffea, 27},  // 247
    {0x7ffffeb, 27},  // 248
    {0xffffffe, 28},  // 249
    {0x7ffffec, 27},  // 250
    {0x7ffffed, 27},  // 251
    {0x7ffffee, 27},  // 252
    {0x7ffffef, 27},  // 253
    {0x7fffff0, 27},  // 254
    {0x3ffffee, 26},  // 255
    {0x3fffffff, 30}, // 256 EOS
}};

// Trie-based Huffman decoder -- O(n) where n is the decoded length.
// The trie is built once on first use from HUFFMAN_TABLE and cached in a
// function-local static.  Each decode walks the trie bit-by-bit, so the
// cost per symbol is proportional to its code length (bounded by 30 bits,
// a constant), eliminating the previous O(n*256) linear scan.

struct HuffmanTrieNode {
    int16_t symbol;       // -1 = internal, 0-255 = symbol, 256 = EOS
    uint16_t children[2]; // indices into the node vector (0 = none)
};

static const std::vector<HuffmanTrieNode>& get_huffman_trie() {
    static const auto trie = []() {
        std::vector<HuffmanTrieNode> nodes;
        nodes.reserve(1024);
        nodes.push_back({-1, {0, 0}}); // root

        for (int sym = 0; sym < 257; ++sym) {
            const auto& entry = HUFFMAN_TABLE[static_cast<size_t>(sym)];
            uint16_t cur = 0;
            for (int bit = static_cast<int>(entry.bits) - 1; bit >= 0; --bit) {
                int b = (entry.code >> bit) & 1;
                if (nodes[cur].children[b] == 0) {
                    nodes[cur].children[b] = static_cast<uint16_t>(nodes.size());
                    nodes.push_back({-1, {0, 0}});
                }
                cur = nodes[cur].children[b];
            }
            nodes[cur].symbol = static_cast<int16_t>(sym);
        }
        return nodes;
    }();
    return trie;
}

static std::optional<std::string> huffman_decode(std::span<const uint8_t> data, size_t encoded_len) {
    const auto& trie = get_huffman_trie();
// ===== Fast Huffman Decoder using prefix lookup table =====
//
// Instead of scanning all 256 symbols per decoded character (O(n*256)),
// we use a two-level approach:
//   Level 1: 10-bit prefix table (1024 entries) for codes <= 10 bits.
//            Covers all common ASCII characters in O(1) per symbol.
//   Level 2: Small sorted array for codes > 10 bits (rare, mostly
//            non-ASCII / control chars). Linear scan of ~130 entries
//            only when needed.
//
// This brings typical-case decoding from O(n*256) down to O(n).

static constexpr int HUFF_LOOKUP_BITS = 10;
static constexpr int HUFF_LOOKUP_SIZE = 1 << HUFF_LOOKUP_BITS; // 1024

struct HuffLookupEntry {
    int16_t symbol; // Decoded symbol (0-255), or -1 if code is longer than HUFF_LOOKUP_BITS
    uint8_t bits;   // Number of bits to consume (0 = need slow path)
};

struct HuffLongCode {
    uint32_t code;
    uint8_t bits;
    uint8_t symbol;
};

struct HuffmanLookup {
    HuffLookupEntry fast_table[HUFF_LOOKUP_SIZE];
    HuffLongCode long_codes[160]; // Codes > 10 bits (upper bound ~140 entries)
    size_t long_code_count = 0;

    HuffmanLookup() {
        // Initialize fast table to "no match"
        for (auto& e : fast_table) {
            e.symbol = -1;
            e.bits = 0;
        }

        for (int sym = 0; sym < 256; ++sym) {
            const auto& h = HUFFMAN_TABLE[static_cast<size_t>(sym)];
            if (h.bits <= HUFF_LOOKUP_BITS) {
                // Fill all table entries whose prefix matches this code.
                // A code of length L occupies 2^(HUFF_LOOKUP_BITS - L) slots.
                int shift = HUFF_LOOKUP_BITS - h.bits;
                int base = static_cast<int>(h.code) << shift;
                int count = 1 << shift;
                for (int j = 0; j < count; ++j) {
                    fast_table[base + j] = {
                        static_cast<int16_t>(sym),
                        h.bits
                    };
                }
            } else {
                long_codes[long_code_count++] = {
                    h.code, h.bits, static_cast<uint8_t>(sym)
                };
            }
        }

        // Sort long codes by bit length (ascending) for early-exit during scan
        std::sort(long_codes, long_codes + long_code_count,
            [](const HuffLongCode& a, const HuffLongCode& b) {
                return a.bits < b.bits || (a.bits == b.bits && a.code < b.code);
            });
    }
};

static const HuffmanLookup& get_huffman_lookup() {
    static const HuffmanLookup instance;
    return instance;
}

static std::optional<std::string> huffman_decode(std::span<const uint8_t> data, size_t encoded_len) {
    const auto& lookup = get_huffman_lookup();
    std::string result;
    result.reserve(encoded_len * 2); // Huffman-encoded strings usually expand

    uint16_t node = 0; // current trie node (0 = root)
    uint8_t bits_without_emit = 0; // track padding bits at end

    for (size_t i = 0; i < encoded_len; ++i) {
        uint8_t byte = data[i];
        for (int bit = 7; bit >= 0; --bit) {
            int b = (byte >> bit) & 1;
            node = trie[node].children[b];
            if (node == 0) {
                return std::nullopt; // invalid code path
            }
            if (trie[node].symbol >= 0) {
                if (trie[node].symbol == 256) {
                    return std::nullopt; // EOS symbol decoded -- RFC 7541 says this is an error
                }
                result += static_cast<char>(trie[node].symbol);
                node = 0; // back to root
                bits_without_emit = 0;
            } else {
                ++bits_without_emit;
                if (bits_without_emit > 30) {
                    return std::nullopt; // no valid code is longer than 30 bits
    uint64_t acc = 0;
    uint8_t bits = 0;

    for (size_t i = 0; i < encoded_len; ++i) {
        acc = (acc << 8) | data[i];
        bits += 8;

        while (bits >= 5) { // Minimum Huffman code is 5 bits
            // Fast path: use the 10-bit prefix lookup table.
            // If we have >= 10 bits, index directly.
            // If we have < 10 bits, left-align into a 10-bit index.
            uint32_t index;
            if (bits >= HUFF_LOOKUP_BITS) {
                index = static_cast<uint32_t>(
                    (acc >> (bits - HUFF_LOOKUP_BITS)) & (HUFF_LOOKUP_SIZE - 1));
            } else {
                index = static_cast<uint32_t>(
                    (acc << (HUFF_LOOKUP_BITS - bits)) & (HUFF_LOOKUP_SIZE - 1));
            }

            const auto& entry = lookup.fast_table[index];
            if (entry.symbol >= 0 && entry.bits <= bits) {
                result += static_cast<char>(entry.symbol);
                bits -= entry.bits;
                acc &= (bits > 0) ? ((1ULL << bits) - 1) : 0;
                continue;
            }

            // Slow path: scan long codes (> 10 bits). Only reached for
            // non-ASCII / rare characters whose Huffman codes exceed 10 bits.
            bool found = false;
            for (size_t lc = 0; lc < lookup.long_code_count; ++lc) {
                const auto& lce = lookup.long_codes[lc];
                if (lce.bits > bits) break; // Sorted by bits; no point checking longer codes
                uint32_t candidate = static_cast<uint32_t>(
                    (acc >> (bits - lce.bits)) & ((1ULL << lce.bits) - 1));
                if (candidate == lce.code) {
                    result += static_cast<char>(lce.symbol);
                    bits -= lce.bits;
                    acc &= (bits > 0) ? ((1ULL << bits) - 1) : 0;
                    found = true;
                    break;
                }
            }

            if (!found) {
                // Check if remaining bits are valid EOS padding (all 1s)
                if (bits <= 7) {
                    uint32_t padding = static_cast<uint32_t>(acc & ((1ULL << bits) - 1));
                    uint32_t expected = static_cast<uint32_t>((1ULL << bits) - 1);
                    if (padding == expected) {
                        return result; // Valid EOS padding
                    }
                }
            }
        }
    }

    // Remaining bits must be valid EOS padding (all 1s, at most 7 bits).
    // After the last emitted symbol we should be on a path towards EOS
    // and every bit we consumed since should have been 1.
    if (node != 0) {
        if (bits_without_emit > 7) return std::nullopt;
        // Verify padding bits were all 1s by checking we're on the
        // all-ones path from root.  Re-walk the last bits_without_emit
        // ones from root -- they must land us at the same node.
        uint16_t check = 0;
        for (uint8_t j = 0; j < bits_without_emit; ++j) {
            check = trie[check].children[1]; // bit = 1
            if (check == 0) return std::nullopt;
        }
        if (check != node) return std::nullopt; // padding wasn't all 1s
    // Check remaining bits are valid EOS padding (all 1s, at most 7 bits)
    if (bits > 0) {
        if (bits > 7) return std::nullopt;
        uint32_t padding = static_cast<uint32_t>(acc & ((1ULL << bits) - 1));
        uint32_t expected = static_cast<uint32_t>((1ULL << bits) - 1);
        if (padding != expected) return std::nullopt;
    }

    return result;
}


// ===== HPACK Static Table (RFC 7541, Appendix A) =====

static const std::pair<std::string_view, std::string_view> STATIC_TABLE[] = {
    {"", ""},                              // 0 (unused)
    {":authority", ""},                    // 1
    {":method", "GET"},                    // 2
    {":method", "POST"},                   // 3
    {":path", "/"},                        // 4
    {":path", "/index.html"},              // 5
    {":scheme", "http"},                   // 6
    {":scheme", "https"},                  // 7
    {":status", "200"},                    // 8
    {":status", "204"},                    // 9
    {":status", "206"},                    // 10
    {":status", "304"},                    // 11
    {":status", "400"},                    // 12
    {":status", "404"},                    // 13
    {":status", "500"},                    // 14
    {"accept-charset", ""},                // 15
    {"accept-encoding", "gzip, deflate"},  // 16
    {"accept-language", ""},               // 17
    {"accept-ranges", ""},                 // 18
    {"accept", ""},                        // 19
    {"access-control-allow-origin", ""},   // 20
    {"age", ""},                           // 21
    {"allow", ""},                         // 22
    {"authorization", ""},                 // 23
    {"cache-control", ""},                 // 24
    {"content-disposition", ""},           // 25
    {"content-encoding", ""},              // 26
    {"content-language", ""},              // 27
    {"content-length", ""},                // 28
    {"content-location", ""},              // 29
    {"content-range", ""},                 // 30
    {"content-type", ""},                  // 31
    {"cookie", ""},                        // 32
    {"date", ""},                          // 33
    {"etag", ""},                          // 34
    {"expect", ""},                        // 35
    {"expires", ""},                       // 36
    {"from", ""},                          // 37
    {"host", ""},                          // 38
    {"if-match", ""},                      // 39
    {"if-modified-since", ""},             // 40
    {"if-none-match", ""},                 // 41
    {"if-range", ""},                      // 42
    {"if-unmodified-since", ""},           // 43
    {"last-modified", ""},                 // 44
    {"link", ""},                          // 45
    {"location", ""},                      // 46
    {"max-forwards", ""},                  // 47
    {"proxy-authenticate", ""},            // 48
    {"proxy-authorization", ""},           // 49
    {"range", ""},                         // 50
    {"referer", ""},                       // 51
    {"refresh", ""},                       // 52
    {"retry-after", ""},                   // 53
    {"server", ""},                        // 54
    {"set-cookie", ""},                    // 55
    {"strict-transport-security", ""},     // 56
    {"transfer-encoding", ""},             // 57
    {"user-agent", ""},                    // 58
    {"vary", ""},                          // 59
    {"via", ""},                           // 60
    {"www-authenticate", ""},              // 61
};
static constexpr size_t STATIC_TABLE_SIZE = sizeof(STATIC_TABLE) / sizeof(STATIC_TABLE[0]) - 1;

// ===== HPACKDecoder =====

HPACKDecoder::HPACKDecoder() = default;

std::pair<std::string_view, std::string_view> HPACKDecoder::static_table_entry(size_t index) {
    if (index > 0 && index <= STATIC_TABLE_SIZE) {
        return STATIC_TABLE[index];
    }
    return {"", ""};
}

size_t HPACKDecoder::static_table_size() {
    return STATIC_TABLE_SIZE;
}

void HPACKDecoder::set_max_table_size(size_t size) {
    max_dynamic_table_size_ = size;
    evict_dynamic_table();
}

void HPACKDecoder::add_to_dynamic_table(std::string name, std::string value) {
    size_t entry_size = name.size() + value.size() + 32;

    // Evict entries if needed
    while (dynamic_table_size_ + entry_size > max_dynamic_table_size_ && !dynamic_table_.empty()) {
        auto& last = dynamic_table_.back();
        dynamic_table_size_ -= last.size();
        dynamic_table_.pop_back();
    }

    if (entry_size <= max_dynamic_table_size_) {
        dynamic_table_.insert(dynamic_table_.begin(), {std::move(name), std::move(value)});
        dynamic_table_size_ += entry_size;
    }
}

void HPACKDecoder::evict_dynamic_table() {
    while (dynamic_table_size_ > max_dynamic_table_size_ && !dynamic_table_.empty()) {
        dynamic_table_size_ -= dynamic_table_.back().size();
        dynamic_table_.pop_back();
    }
}

std::optional<std::pair<std::string, std::string>> HPACKDecoder::lookup(size_t index) const {
    if (index == 0) return std::nullopt;

    if (index <= STATIC_TABLE_SIZE) {
        auto [n, v] = STATIC_TABLE[index];
        return std::pair{std::string(n), std::string(v)};
    }

    size_t dyn_index = index - STATIC_TABLE_SIZE - 1;
    if (dyn_index < dynamic_table_.size()) {
        auto& entry = dynamic_table_[dyn_index];
        return std::pair{entry.name, entry.value};
    }

    return std::nullopt;
}

std::optional<uint64_t> HPACKDecoder::decode_integer(
    std::span<const uint8_t>& data, uint8_t prefix_bits) {
    if (data.empty()) return std::nullopt;

    uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1);
    uint64_t value = data[0] & max_prefix;
    data = data.subspan(1);

    if (value < max_prefix) return value;

    uint64_t m = 0;
    do {
        if (data.empty()) return std::nullopt;
        uint8_t b = data[0];
        data = data.subspan(1);
        value += static_cast<uint64_t>(b & 0x7F) << m;
        m += 7;
        if ((b & 0x80) == 0) break;
        if (m > 63) return std::nullopt; // Overflow protection
    } while (true);

    return value;
}

std::optional<std::string> HPACKDecoder::decode_string(std::span<const uint8_t>& data) {
    if (data.empty()) return std::nullopt;

    bool is_huffman = (data[0] & 0x80) != 0;
    auto length = decode_integer(data, 7);
    if (!length || *length > data.size()) return std::nullopt;

    auto str_len = static_cast<size_t>(*length);

    if (is_huffman) {
        // Decode using Huffman table from RFC 7541 Appendix B
        auto decoded = huffman_decode(data.subspan(0, str_len), str_len);
        data = data.subspan(str_len);
        return decoded;
    }

    std::string result(reinterpret_cast<const char*>(data.data()), str_len);
    data = data.subspan(str_len);
    return result;
}

std::optional<std::vector<std::pair<std::string, std::string>>>
HPACKDecoder::decode(std::span<const uint8_t> data) {
    std::vector<std::pair<std::string, std::string>> headers;

    while (!data.empty()) {
        uint8_t byte = data[0];

        if (byte & 0x80) {
            // Indexed Header Field (Section 6.1)
            auto index = decode_integer(data, 7);
            if (!index) return std::nullopt;

            auto entry = lookup(static_cast<size_t>(*index));
            if (!entry) return std::nullopt;
            headers.push_back(*entry);

        } else if (byte & 0x40) {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            auto index = decode_integer(data, 6);
            if (!index) return std::nullopt;

            std::string name, value;
            if (*index > 0) {
                auto entry = lookup(static_cast<size_t>(*index));
                if (!entry) return std::nullopt;
                name = entry->first;
            } else {
                auto n = decode_string(data);
                if (!n) return std::nullopt;
                name = std::move(*n);
            }

            auto v = decode_string(data);
            if (!v) return std::nullopt;
            value = std::move(*v);

            add_to_dynamic_table(name, value);
            headers.emplace_back(std::move(name), std::move(value));

        } else if (byte & 0x20) {
            // Dynamic Table Size Update (Section 6.3)
            auto size = decode_integer(data, 5);
            if (!size) return std::nullopt;
            set_max_table_size(static_cast<size_t>(*size));

        } else {
            // Literal Header Field without Indexing / Never Indexed
            uint8_t prefix = (byte & 0x10) ? 4 : 4;
            auto index = decode_integer(data, prefix);
            if (!index) return std::nullopt;

            std::string name, value;
            if (*index > 0) {
                auto entry = lookup(static_cast<size_t>(*index));
                if (!entry) return std::nullopt;
                name = entry->first;
            } else {
                auto n = decode_string(data);
                if (!n) return std::nullopt;
                name = std::move(*n);
            }

            auto v = decode_string(data);
            if (!v) return std::nullopt;
            value = std::move(*v);

            headers.emplace_back(std::move(name), std::move(value));
        }
    }

    return headers;
}

// ===== HPACKEncoder =====

void HPACKEncoder::encode_integer(std::string& out, uint64_t value, uint8_t prefix_bits, uint8_t pattern) {
    uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1);

    if (value < max_prefix) {
        out += static_cast<char>(pattern | static_cast<uint8_t>(value));
    } else {
        out += static_cast<char>(pattern | max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            out += static_cast<char>((value & 0x7F) | 0x80);
            value >>= 7;
        }
        out += static_cast<char>(value);
    }
}

void HPACKEncoder::encode_string(std::string& out, std::string_view str) {
    // Without Huffman encoding for simplicity
    encode_integer(out, str.size(), 7, 0x00);
    out.append(str);
}

std::string HPACKEncoder::encode(const std::vector<std::pair<std::string, std::string>>& headers) {
    std::string result;

    for (const auto& [name, value] : headers) {
        // Check static table for indexed name
        bool found = false;
        for (size_t i = 1; i <= STATIC_TABLE_SIZE; ++i) {
            if (STATIC_TABLE[i].first == name) {
                if (STATIC_TABLE[i].second == value) {
                    // Fully indexed
                    encode_integer(result, i, 7, 0x80);
                    found = true;
                    break;
                }
                // Name indexed, literal value (without indexing)
                encode_integer(result, i, 4, 0x00);
                encode_string(result, value);
                found = true;
                break;
            }
        }

        if (!found) {
            // Literal without indexing, new name
            result += '\x00';
            encode_string(result, name);
            encode_string(result, value);
        }
    }

    return result;
}

// ===== Http2Connection =====

Http2Connection::Http2Connection(RequestHandler handler)
    : handler_(std::move(handler)) {}

std::string Http2Connection::process_input(std::span<const char> data) {
    buffer_.append(data.data(), data.size());
    std::string output;

    // Check for client preface
    if (!preface_received_) {
        if (buffer_.size() < CLIENT_PREFACE.size()) {
            return output; // Need more data
        }

        if (buffer_.substr(0, CLIENT_PREFACE.size()) != CLIENT_PREFACE) {
            LOG_WARN("HTTP/2: Invalid client connection preface");
            output += build_goaway(H2Error::PROTOCOL_ERROR, "Invalid preface");
            goaway_sent_ = true;
            return output;
        }

        buffer_.erase(0, CLIENT_PREFACE.size());
        preface_received_ = true;

        // Send server settings
        output += build_settings_frame();
        settings_sent_ = true;
    }

    // Process frames
    while (true) {
        auto frame = parse_frame();
        if (!frame) break;

        output += handle_frame(*frame);

        if (goaway_sent_) break;
    }

    return output;
}

std::optional<H2Frame> Http2Connection::parse_frame() {
    // Frame header is 9 bytes
    if (buffer_.size() < 9) return std::nullopt;

    H2Frame frame;

    // Length (24 bits)
    frame.length = (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[0])) << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[1])) << 8) |
                   static_cast<uint32_t>(static_cast<uint8_t>(buffer_[2]));

    // Type (8 bits)
    frame.type = static_cast<H2FrameType>(buffer_[3]);

    // Flags (8 bits)
    frame.flags = static_cast<uint8_t>(buffer_[4]);

    // Stream ID (31 bits, MSB reserved)
    frame.stream_id = (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[5]) & 0x7F) << 24) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[6])) << 16) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[7])) << 8) |
                      static_cast<uint32_t>(static_cast<uint8_t>(buffer_[8]));

    // Check frame size
    if (frame.length > max_frame_size_) {
        return std::nullopt;
    }

    // Check we have full payload
    if (buffer_.size() < 9 + frame.length) return std::nullopt;

    frame.payload = buffer_.substr(9, frame.length);
    buffer_.erase(0, 9 + frame.length);

    return frame;
}

std::string Http2Connection::handle_frame(const H2Frame& frame) {
    switch (frame.type) {
        case H2FrameType::SETTINGS:    return handle_settings(frame);
        case H2FrameType::HEADERS:     return handle_headers(frame);
        case H2FrameType::DATA:        return handle_data(frame);
        case H2FrameType::WINDOW_UPDATE: return handle_window_update(frame);
        case H2FrameType::PING:        return handle_ping(frame);
        case H2FrameType::GOAWAY:      return handle_goaway(frame);
        case H2FrameType::RST_STREAM:  return {}; // Acknowledged
        case H2FrameType::PRIORITY:    return {}; // Advisory only
        default:
            // Unknown frame types are ignored per spec
            return {};
    }
}

std::string Http2Connection::handle_settings(const H2Frame& frame) {
    if (frame.has_flag(0x1)) {
        // Settings ACK - no payload
        return {};
    }

    // Parse settings
    if (frame.payload.size() % 6 != 0) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR, "Invalid SETTINGS frame size");
    }

    for (size_t i = 0; i < frame.payload.size(); i += 6) {
        uint16_t id = (static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[i])) << 8) |
                      static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[i + 1]));
        uint32_t value = (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 2])) << 24) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 3])) << 16) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 4])) << 8) |
                         static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 5]));

        switch (static_cast<H2Setting>(id)) {
            case H2Setting::HEADER_TABLE_SIZE:
                header_table_size_ = value;
                decoder_.set_max_table_size(value);
                break;
            case H2Setting::MAX_CONCURRENT_STREAMS:
                max_concurrent_streams_ = value;
                break;
            case H2Setting::INITIAL_WINDOW_SIZE:
                if (value > 0x7FFFFFFF) {
                    return build_goaway(H2Error::FLOW_CONTROL_ERROR);
                }
                initial_window_size_ = value;
                break;
            case H2Setting::MAX_FRAME_SIZE:
                if (value < 16384 || value > 16777215) {
                    return build_goaway(H2Error::PROTOCOL_ERROR);
                }
                max_frame_size_ = value;
                break;
            default:
                break; // Unknown settings are ignored
        }
    }

    // Send SETTINGS ACK
    return build_settings_frame(true);
}

std::string Http2Connection::handle_headers(const H2Frame& frame) {
    if (frame.stream_id == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR, "HEADERS on stream 0");
    }

    auto& stream = get_or_create_stream(frame.stream_id);

    std::string_view payload(frame.payload);

    // Handle padding
    size_t pad_length = 0;
    size_t offset = 0;
    if (frame.has_flag(H2Flags::PADDED)) {
        if (payload.empty()) return build_goaway(H2Error::PROTOCOL_ERROR);
        pad_length = static_cast<uint8_t>(payload[0]);
        offset = 1;
    }

    // Handle priority
    if (frame.has_flag(H2Flags::PRIORITY)) {
        offset += 5; // Stream dependency (4) + Weight (1)
    }

    if (offset + pad_length > payload.size()) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto header_data = payload.substr(offset, payload.size() - offset - pad_length);
    stream.header_block.append(header_data);

    if (frame.has_flag(H2Flags::END_HEADERS)) {
        // Decode headers
        auto header_bytes = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(stream.header_block.data()),
            stream.header_block.size()
        );

        auto decoded = decoder_.decode(header_bytes);
        if (!decoded) {
            return build_goaway(H2Error::COMPRESSION_ERROR);
        }

        // Build HttpRequest from decoded headers
        for (const auto& [name, value] : *decoded) {
            if (name == ":method") stream.request.method_str = value;
            else if (name == ":path") {
                stream.request.uri = value;
                stream.request.path = value;
                auto qmark = value.find('?');
                if (qmark != std::string::npos) {
                    stream.request.path = value.substr(0, qmark);
                    stream.request.query_string = value.substr(qmark + 1);
                }
            }
            else if (name == ":authority") stream.request.headers["Host"] = value;
            else if (name == ":scheme") {} // Not needed for routing
            else if (!name.empty() && name[0] != ':') {
                stream.request.headers[name] = value;
            }
        }

        // Parse method
        if (stream.request.method_str == "GET") stream.request.method = HttpMethod::GET;
        else if (stream.request.method_str == "POST") stream.request.method = HttpMethod::POST;
        else if (stream.request.method_str == "HEAD") stream.request.method = HttpMethod::HEAD;
        else if (stream.request.method_str == "PUT") stream.request.method = HttpMethod::PUT;
        else if (stream.request.method_str == "DELETE") stream.request.method = HttpMethod::DELETE_;
        else if (stream.request.method_str == "OPTIONS") stream.request.method = HttpMethod::OPTIONS;
        else stream.request.method = HttpMethod::UNKNOWN;

        stream.request.version = "HTTP/2";
        stream.headers_complete = true;
        stream.header_block.clear();

        // If END_STREAM, process request immediately
        if (frame.has_flag(H2Flags::END_STREAM)) {
            stream.state = H2StreamState::HALF_CLOSED_REMOTE;

            // Handle request
            auto response = handler_(stream.request);
            LOG_INFO("HTTP/2 stream " + std::to_string(frame.stream_id) + " " +
                     stream.request.method_str + " " + stream.request.uri +
                     " -> " + std::to_string(response.status_code));

            return build_headers_response(frame.stream_id, response);
        } else {
            stream.state = H2StreamState::OPEN;
        }
    }

    return {};
}

std::string Http2Connection::handle_data(const H2Frame& frame) {
    if (frame.stream_id == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto it = streams_.find(frame.stream_id);
    if (it == streams_.end()) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto& stream = it->second;
    stream.request.body.append(frame.payload);

    if (frame.has_flag(H2Flags::END_STREAM)) {
        stream.state = H2StreamState::HALF_CLOSED_REMOTE;

        if (stream.headers_complete) {
            auto response = handler_(stream.request);
            return build_headers_response(frame.stream_id, response);
        }
    }

    // Send WINDOW_UPDATE for connection and stream
    std::string output;
    if (frame.length > 0) {
        uint32_t increment = frame.length;
        // Connection-level window update
        char buf[4];
        uint32_t net_inc = htonl(increment);
        std::memcpy(buf, &net_inc, 4);
        output += build_frame(H2FrameType::WINDOW_UPDATE, 0, 0, std::string_view(buf, 4));
        // Stream-level window update
        output += build_frame(H2FrameType::WINDOW_UPDATE, 0, frame.stream_id, std::string_view(buf, 4));
    }

    return output;
}

std::string Http2Connection::handle_window_update(const H2Frame& frame) {
    if (frame.payload.size() != 4) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR);
    }

    uint32_t increment = (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[0]) & 0x7F) << 24) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[1])) << 16) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[2])) << 8) |
                         static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[3]));

    if (increment == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    if (frame.stream_id == 0) {
        connection_window_ += static_cast<int32_t>(increment);
    } else {
        auto it = streams_.find(frame.stream_id);
        if (it != streams_.end()) {
            it->second.window_size += static_cast<int32_t>(increment);
        }
    }

    return {};
}

std::string Http2Connection::handle_ping(const H2Frame& frame) {
    if (frame.payload.size() != 8) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR);
    }
    if (frame.has_flag(0x1)) {
        return {}; // ACK, ignore
    }
    // Echo back with ACK flag
    return build_frame(H2FrameType::PING, 0x1, 0, frame.payload);
}

std::string Http2Connection::handle_goaway([[maybe_unused]] const H2Frame& frame) {
    goaway_sent_ = true;
    return {};
}

// ===== Frame building =====

std::string Http2Connection::build_frame(H2FrameType type, uint8_t flags,
                                          uint32_t stream_id, std::string_view payload) {
    std::string frame;
    frame.resize(9 + payload.size());

    uint32_t len = static_cast<uint32_t>(payload.size());
    frame[0] = static_cast<char>((len >> 16) & 0xFF);
    frame[1] = static_cast<char>((len >> 8) & 0xFF);
    frame[2] = static_cast<char>(len & 0xFF);
    frame[3] = static_cast<char>(type);
    frame[4] = static_cast<char>(flags);
    frame[5] = static_cast<char>((stream_id >> 24) & 0x7F);
    frame[6] = static_cast<char>((stream_id >> 16) & 0xFF);
    frame[7] = static_cast<char>((stream_id >> 8) & 0xFF);
    frame[8] = static_cast<char>(stream_id & 0xFF);

    if (!payload.empty()) {
        std::memcpy(frame.data() + 9, payload.data(), payload.size());
    }

    return frame;
}

std::string Http2Connection::build_settings_frame(bool ack) {
    if (ack) {
        return build_frame(H2FrameType::SETTINGS, 0x1, 0, "");
    }

    // Send our settings
    std::string payload;
    auto add_setting = [&payload](H2Setting id, uint32_t value) {
        uint16_t net_id = htons(static_cast<uint16_t>(id));
        uint32_t net_val = htonl(value);
        payload.append(reinterpret_cast<const char*>(&net_id), 2);
        payload.append(reinterpret_cast<const char*>(&net_val), 4);
    };

    add_setting(H2Setting::MAX_CONCURRENT_STREAMS, 100);
    add_setting(H2Setting::INITIAL_WINDOW_SIZE, 65535);
    add_setting(H2Setting::MAX_FRAME_SIZE, 16384);

    return build_frame(H2FrameType::SETTINGS, 0, 0, payload);
}

std::string Http2Connection::build_headers_response(uint32_t stream_id, const HttpResponse& resp) {
    std::string output;

    // Encode response headers
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back(":status", std::to_string(resp.status_code));

    for (const auto& [name, value] : resp.headers) {
        std::string lower_name(name);
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        headers.emplace_back(std::move(lower_name), value);
    }

    if (!resp.body.empty()) {
        bool has_cl = false;
        for (const auto& [n, v] : headers) {
            if (n == "content-length") { has_cl = true; break; }
        }
        if (!has_cl) {
            headers.emplace_back("content-length", std::to_string(resp.body.size()));
        }
    }

    headers.emplace_back("server", "JustServer/1.0");

    auto encoded = encoder_.encode(headers);

    uint8_t flags = H2Flags::END_HEADERS;
    if (resp.body.empty()) {
        flags |= H2Flags::END_STREAM;
    }

    output += build_frame(H2FrameType::HEADERS, flags, stream_id, encoded);

    // Send body as DATA frames
    if (!resp.body.empty()) {
        size_t offset = 0;
        while (offset < resp.body.size()) {
            size_t chunk = std::min(resp.body.size() - offset, static_cast<size_t>(max_frame_size_));
            bool last = (offset + chunk >= resp.body.size());
            uint8_t data_flags = last ? H2Flags::END_STREAM : 0;
            output += build_frame(H2FrameType::DATA, data_flags, stream_id,
                                  std::string_view(resp.body.data() + offset, chunk));
            offset += chunk;
        }
    }

    return output;
}

std::string Http2Connection::build_goaway(H2Error error, std::string_view debug) {
    goaway_sent_ = true;

    std::string payload;
    payload.resize(8 + debug.size());

    uint32_t last_id = htonl(last_stream_id_);
    uint32_t err_code = htonl(static_cast<uint32_t>(error));
    std::memcpy(payload.data(), &last_id, 4);
    std::memcpy(payload.data() + 4, &err_code, 4);
    if (!debug.empty()) {
        std::memcpy(payload.data() + 8, debug.data(), debug.size());
    }

    return build_frame(H2FrameType::GOAWAY, 0, 0, payload);
}

H2Stream& Http2Connection::get_or_create_stream(uint32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        auto [new_it, _] = streams_.emplace(stream_id, H2Stream{});
        new_it->second.id = stream_id;
        new_it->second.state = H2StreamState::IDLE;
        new_it->second.window_size = static_cast<int32_t>(initial_window_size_);
        if (stream_id > last_stream_id_) {
            last_stream_id_ = stream_id;
        }
        return new_it->second;
    }
    return it->second;
}

} // namespace js
