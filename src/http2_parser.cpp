#include "pntp/http2_parser.h"
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <sstream>
#include <iostream>

// ═════════════════════════════════════════════════════════════════════
// HPACK Static Table (RFC 7541 Appendix A) — 61 entries
// ═════════════════════════════════════════════════════════════════════

static const std::array<HpackHeaderField, 61> kStaticTable = {{
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", ""},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
}};

const HpackHeaderField& HpackStaticTable::get(size_t index) {
    // RFC 7541: 1-indexed, index 1-61
    if (index < 1 || index > SIZE)
        throw std::out_of_range("HPACK static table index out of range");
    return kStaticTable[index - 1];
}

size_t HpackStaticTable::findName(const std::string& name) {
    for (size_t i = 0; i < kStaticTable.size(); ++i) {
        if (kStaticTable[i].name == name)
            return i + 1;  // 1-indexed
    }
    return 0;
}

// ═════════════════════════════════════════════════════════════════════
// HPACK Huffman Codec (RFC 7541 Appendix B)
// ═════════════════════════════════════════════════════════════════════

struct HuffmanCode {
    uint32_t code;
    uint8_t bits;
};

// Huffman codes for 0-255 (RFC 7541 Appendix B)
// Huffman codes for 0-255 (RFC 7541 Appendix B) — generated from nghttp2's verified table
static const std::array<HuffmanCode, 256> kHuffmanTable = {{
    {0x1ff8, 13},
    {0x7fffd8, 23},
    {0xfffffe2, 28},
    {0xfffffe3, 28},
    {0xfffffe4, 28},
    {0xfffffe5, 28},
    {0xfffffe6, 28},
    {0xfffffe7, 28},
    {0xfffffe8, 28},
    {0xffffea, 24},
    {0x3ffffffc, 30},
    {0xfffffe9, 28},
    {0xfffffea, 28},
    {0x3ffffffd, 30},
    {0xfffffeb, 28},
    {0xfffffec, 28},
    {0xfffffed, 28},
    {0xfffffee, 28},
    {0xfffffef, 28},
    {0xffffff0, 28},
    {0xffffff1, 28},
    {0xffffff2, 28},
    {0x3ffffffe, 30},
    {0xffffff3, 28},
    {0xffffff4, 28},
    {0xffffff5, 28},
    {0xffffff6, 28},
    {0xffffff7, 28},
    {0xffffff8, 28},
    {0xffffff9, 28},
    {0xffffffa, 28},
    {0xffffffb, 28},
    {0x14, 6},
    {0x3f8, 10},
    {0x3f9, 10},
    {0xffa, 12},
    {0x1ff9, 13},
    {0x15, 6},
    {0xf8, 8},
    {0x7fa, 11},
    {0x3fa, 10},
    {0x3fb, 10},
    {0xf9, 8},
    {0x7fb, 11},
    {0xfa, 8},
    {0x16, 6},
    {0x17, 6},
    {0x18, 6},
    {0x0, 5},
    {0x1, 5},
    {0x2, 5},
    {0x19, 6},
    {0x1a, 6},
    {0x1b, 6},
    {0x1c, 6},
    {0x1d, 6},
    {0x1e, 6},
    {0x1f, 6},
    {0x5c, 7},
    {0xfb, 8},
    {0x7ffc, 15},
    {0x20, 6},
    {0xffb, 12},
    {0x3fc, 10},
    {0x1ffa, 13},
    {0x21, 6},
    {0x5d, 7},
    {0x5e, 7},
    {0x5f, 7},
    {0x60, 7},
    {0x61, 7},
    {0x62, 7},
    {0x63, 7},
    {0x64, 7},
    {0x65, 7},
    {0x66, 7},
    {0x67, 7},
    {0x68, 7},
    {0x69, 7},
    {0x6a, 7},
    {0x6b, 7},
    {0x6c, 7},
    {0x6d, 7},
    {0x6e, 7},
    {0x6f, 7},
    {0x70, 7},
    {0x71, 7},
    {0x72, 7},
    {0xfc, 8},
    {0x73, 7},
    {0xfd, 8},
    {0x1ffb, 13},
    {0x7fff0, 19},
    {0x1ffc, 13},
    {0x3ffc, 14},
    {0x22, 6},
    {0x7ffd, 15},
    {0x3, 5},
    {0x23, 6},
    {0x4, 5},
    {0x24, 6},
    {0x5, 5},
    {0x25, 6},
    {0x26, 6},
    {0x27, 6},
    {0x6, 5},
    {0x74, 7},
    {0x75, 7},
    {0x28, 6},
    {0x29, 6},
    {0x2a, 6},
    {0x7, 5},
    {0x2b, 6},
    {0x76, 7},
    {0x2c, 6},
    {0x8, 5},
    {0x9, 5},
    {0x2d, 6},
    {0x77, 7},
    {0x78, 7},
    {0x79, 7},
    {0x7a, 7},
    {0x7b, 7},
    {0x7ffe, 15},
    {0x7fc, 11},
    {0x3ffd, 14},
    {0x1ffd, 13},
    {0xffffffc, 28},
    {0xfffe6, 20},
    {0x3fffd2, 22},
    {0xfffe7, 20},
    {0xfffe8, 20},
    {0x3fffd3, 22},
    {0x3fffd4, 22},
    {0x3fffd5, 22},
    {0x7fffd9, 23},
    {0x3fffd6, 22},
    {0x7fffda, 23},
    {0x7fffdb, 23},
    {0x7fffdc, 23},
    {0x7fffdd, 23},
    {0x7fffde, 23},
    {0xffffeb, 24},
    {0x7fffdf, 23},
    {0xffffec, 24},
    {0xffffed, 24},
    {0x3fffd7, 22},
    {0x7fffe0, 23},
    {0xffffee, 24},
    {0x7fffe1, 23},
    {0x7fffe2, 23},
    {0x7fffe3, 23},
    {0x7fffe4, 23},
    {0x1fffdc, 21},
    {0x3fffd8, 22},
    {0x7fffe5, 23},
    {0x3fffd9, 22},
    {0x7fffe6, 23},
    {0x7fffe7, 23},
    {0xffffef, 24},
    {0x3fffda, 22},
    {0x1fffdd, 21},
    {0xfffe9, 20},
    {0x3fffdb, 22},
    {0x3fffdc, 22},
    {0x7fffe8, 23},
    {0x7fffe9, 23},
    {0x1fffde, 21},
    {0x7fffea, 23},
    {0x3fffdd, 22},
    {0x3fffde, 22},
    {0xfffff0, 24},
    {0x1fffdf, 21},
    {0x3fffdf, 22},
    {0x7fffeb, 23},
    {0x7fffec, 23},
    {0x1fffe0, 21},
    {0x1fffe1, 21},
    {0x3fffe0, 22},
    {0x1fffe2, 21},
    {0x7fffed, 23},
    {0x3fffe1, 22},
    {0x7fffee, 23},
    {0x7fffef, 23},
    {0xfffea, 20},
    {0x3fffe2, 22},
    {0x3fffe3, 22},
    {0x3fffe4, 22},
    {0x7ffff0, 23},
    {0x3fffe5, 22},
    {0x3fffe6, 22},
    {0x7ffff1, 23},
    {0x3ffffe0, 26},
    {0x3ffffe1, 26},
    {0xfffeb, 20},
    {0x7fff1, 19},
    {0x3fffe7, 22},
    {0x7ffff2, 23},
    {0x3fffe8, 22},
    {0x1ffffec, 25},
    {0x3ffffe2, 26},
    {0x3ffffe3, 26},
    {0x3ffffe4, 26},
    {0x7ffffde, 27},
    {0x7ffffdf, 27},
    {0x3ffffe5, 26},
    {0xfffff1, 24},
    {0x1ffffed, 25},
    {0x7fff2, 19},
    {0x1fffe3, 21},
    {0x3ffffe6, 26},
    {0x7ffffe0, 27},
    {0x7ffffe1, 27},
    {0x3ffffe7, 26},
    {0x7ffffe2, 27},
    {0xfffff2, 24},
    {0x1fffe4, 21},
    {0x1fffe5, 21},
    {0x3ffffe8, 26},
    {0x3ffffe9, 26},
    {0xffffffd, 28},
    {0x7ffffe3, 27},
    {0x7ffffe4, 27},
    {0x7ffffe5, 27},
    {0xfffec, 20},
    {0xfffff3, 24},
    {0xfffed, 20},
    {0x1fffe6, 21},
    {0x3fffe9, 22},
    {0x1fffe7, 21},
    {0x1fffe8, 21},
    {0x7ffff3, 23},
    {0x3fffea, 22},
    {0x3fffeb, 22},
    {0x1ffffee, 25},
    {0x1ffffef, 25},
    {0xfffff4, 24},
    {0xfffff5, 24},
    {0x3ffffea, 26},
    {0x7ffff4, 23},
    {0x3ffffeb, 26},
    {0x7ffffe6, 27},
    {0x3ffffec, 26},
    {0x3ffffed, 26},
    {0x7ffffe7, 27},
    {0x7ffffe8, 27},
    {0x7ffffe9, 27},
    {0x7ffffea, 27},
    {0x7ffffeb, 27},
    {0xffffffe, 28},
    {0x7ffffec, 27},
    {0x7ffffed, 27},
    {0x7ffffee, 27},
    {0x7ffffef, 27},
    {0x7fffff0, 27},
    {0x3ffffee, 26}
}};

// EOS symbol (256) — used for padding
static constexpr uint32_t kHuffmanEOS = 0x3fffffff;
static constexpr uint8_t kHuffmanEOSBits = 30;

std::vector<uint8_t> HpackHuffman::encode(const std::string& input) {
    std::vector<uint8_t> out;
    if (input.empty()) return out;

    uint64_t bits = 0;
    uint8_t nbits = 0;

    for (unsigned char c : input) {
        const auto& hc = kHuffmanTable[c];
        bits = (bits << hc.bits) | hc.code;
        nbits += hc.bits;

        while (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<uint8_t>(bits >> nbits));
            bits &= (1ULL << nbits) - 1;
        }
    }

    // Pad with EOS bits
    if (nbits > 0) {
        bits = (bits << (8 - nbits)) | (kHuffmanEOS >> (kHuffmanEOSBits - (8 - nbits)));
        out.push_back(static_cast<uint8_t>(bits));
    }

    return out;
}

std::string HpackHuffman::decode(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    std::string result;
    result.reserve(len * 2);
    uint64_t bits = 0;
    int nbits = 0;
    size_t input_pos = 0;
    // Safety: at most result chars = len * 2
    size_t max_iters = len * 4;

    while (input_pos < len && result.size() < max_iters) {
        bits = (bits << 8) | data[input_pos++];
        nbits += 8;
        int safety = 0;
        while (nbits > 0 && safety < 256) {
            ++safety;
            bool found = false;
            for (int ch = 0; ch < 256; ++ch) {
                const auto& hc = kHuffmanTable[ch];
                if (nbits < hc.bits) continue;
                int shift = nbits - hc.bits;
                uint32_t expected = static_cast<uint32_t>(bits >> shift);
                if (hc.bits < 32) {
                    expected &= (1U << hc.bits) - 1;
                }
                if (expected == hc.code) {
                    result.push_back(static_cast<char>(ch));
                    nbits -= hc.bits;
                    bits &= (1ULL << nbits) - 1;
                    found = true;
                    break;
                }
            }
            if (!found) break;
        }
    }
    return result;
}

// ═════════════════════════════════════════════════════════════════════
// HPACK Dynamic Table
// ═════════════════════════════════════════════════════════════════════

HpackDynamicTable::HpackDynamicTable() {}

size_t HpackDynamicTable::entrySize(const HpackHeaderField& e) const {
    return e.name.size() + e.value.size() + 32;
}

void HpackDynamicTable::evict() {
    while (current_size_ > max_size_ && !entries_.empty()) {
        auto& last = entries_.back();
        current_size_ -= entrySize(last);
        entries_.pop_back();
    }
}

void HpackDynamicTable::add(const HpackHeaderField& entry) {
    size_t esize = entrySize(entry);
    if (esize > max_size_) {
        clear();
        return;
    }
    entries_.insert(entries_.begin(), entry);
    current_size_ += esize;
    evict();
}

const HpackHeaderField* HpackDynamicTable::get(size_t index) const {
    // Dynamic table indices start after static table (62+)
    // Index 62 = entry 0, Index 63 = entry 1, etc.
    size_t dyn_idx = index - HpackStaticTable::SIZE - 1;
    if (dyn_idx >= entries_.size()) return nullptr;
    return &entries_[dyn_idx];
}

size_t HpackDynamicTable::findName(const std::string& name) const {
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].name == name)
            return HpackStaticTable::SIZE + 1 + i;
    }
    return 0;
}

void HpackDynamicTable::setMaxSize(size_t max_size) {
    max_size_ = max_size;
    evict();
}

void HpackDynamicTable::clear() {
    entries_.clear();
    current_size_ = 0;
}

// ═════════════════════════════════════════════════════════════════════
// HPACK Encoder
// ═════════════════════════════════════════════════════════════════════

HpackEncoder::HpackEncoder() {}

void HpackEncoder::setTableSize(size_t size) {
    dynamic_table_.setMaxSize(size);
    table_size_sent_ = false;
}

void HpackEncoder::clearDynamicTable() {
    dynamic_table_.clear();
}

void HpackEncoder::encodeInteger(std::vector<uint8_t>& out, uint64_t value, uint8_t nbits) {
    uint8_t mask = static_cast<uint8_t>((1U << nbits) - 1);
    if (value < mask) {
        out.push_back(static_cast<uint8_t>(value));
    } else {
        out.push_back(mask);
        value -= mask;
        while (value >= 128) {
            out.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
            value >>= 7;
        }
        out.push_back(static_cast<uint8_t>(value));
    }
}

// Encode integer with prefix bits already set in the first byte
static void encodeIntegerWithPrefix(std::vector<uint8_t>& out, uint8_t prefix_byte,
                                      uint64_t value, uint8_t nbits) {
    uint8_t mask = static_cast<uint8_t>((1U << nbits) - 1);
    if (value < mask) {
        out.push_back(static_cast<uint8_t>(prefix_byte | value));
    } else {
        out.push_back(static_cast<uint8_t>(prefix_byte | mask));
        value -= mask;
        while (value >= 128) {
            out.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
            value >>= 7;
        }
        out.push_back(static_cast<uint8_t>(value));
    }
}

void HpackEncoder::encodeString(std::vector<uint8_t>& out, const std::string& str) {
    // Use plain (non-Huffman) string encoding — valid per RFC 7541
    encodeIntegerWithPrefix(out, 0x00, str.size(), 7);
    out.insert(out.end(), str.begin(), str.end());
}

void HpackEncoder::encodeIndexed(std::vector<uint8_t>& out, size_t index) {
    encodeIntegerWithPrefix(out, 0x80, index, 7);
}

void HpackEncoder::encodeLiteral(std::vector<uint8_t>& out, const std::string& name,
                                  const std::string& value, bool incremental) {
    if (incremental) {
        // Check static/dynamic table for name
        size_t name_idx = HpackStaticTable::findName(name);
        if (name_idx == 0) name_idx = dynamic_table_.findName(name);

        if (name_idx > 0) {
            // Literal with incremental indexing, indexed name
            encodeIntegerWithPrefix(out, 0x40, name_idx, 6);
        } else {
            // Literal with incremental indexing, new name
            encodeIntegerWithPrefix(out, 0x40, 0, 6);  // Index 0 = new name
            encodeString(out, name);
        }
        encodeString(out, value);

        // Add to dynamic table
        dynamic_table_.add({name, value});
    } else {
        // Literal without indexing
        size_t name_idx = HpackStaticTable::findName(name);
        if (name_idx == 0) name_idx = dynamic_table_.findName(name);

        if (name_idx > 0) {
            encodeIntegerWithPrefix(out, 0x00, name_idx, 4);
        } else {
            encodeIntegerWithPrefix(out, 0x00, 0, 4);
            encodeString(out, name);
        }
        encodeString(out, value);
    }
}

std::vector<uint8_t> HpackEncoder::encode(const std::vector<HpackHeaderField>& headers, bool& error) {
    std::vector<uint8_t> out;
    error = false;

    if (headers.empty()) return out;

    // Emit table size update if needed
    if (!table_size_sent_) {
        encodeIntegerWithPrefix(out, 0x20, dynamic_table_.maxSize(), 5);
        table_size_sent_ = true;
    }

    for (const auto& h : headers) {
        // Try indexed (both name and value match)
        size_t idx = HpackStaticTable::findName(h.name);
        if (idx > 0) {
            try {
                const auto& entry = HpackStaticTable::get(idx);
                if (entry.value == h.value) {
                    encodeIndexed(out, idx);
                    continue;
                }
            } catch (...) {}
        }
        // Try dynamic table for full match
        for (size_t di = HpackStaticTable::SIZE + 1; di < HpackStaticTable::SIZE + 1 + dynamic_table_.size(); ++di) {
            auto* entry = dynamic_table_.get(di);
            if (entry && entry->name == h.name && entry->value == h.value) {
                encodeIndexed(out, di);
                goto next_header;
            }
        }

        // Literal with incremental indexing
        encodeLiteral(out, h.name, h.value, true);
        next_header:;
    }

    return out;
}

// ═════════════════════════════════════════════════════════════════════
// HPACK Decoder
// ═════════════════════════════════════════════════════════════════════

HpackDecoder::HpackDecoder() {}

void HpackDecoder::setTableSize(size_t size) {
    dynamic_table_.setMaxSize(size);
}

uint64_t HpackDecoder::decodeInteger(const uint8_t*& pos, const uint8_t* end, uint8_t nbits) {
    if (pos >= end) return 0;
    uint8_t mask = static_cast<uint8_t>((1U << nbits) - 1);
    uint64_t value = (*pos) & mask;
    if (value < mask) {
        ++pos;
        return value;
    }
    ++pos;
    uint64_t shift = 0;
    while (pos < end) {
        uint8_t byte = *pos;
        ++pos;
        value += static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    return value;
}

std::string HpackDecoder::decodeString(const uint8_t*& pos, const uint8_t* end, bool& error) {
    if (pos >= end) { error = true; return {}; }
    bool huffman = (*pos & 0x80) != 0;
    uint64_t len = decodeInteger(pos, end, 7);
    if (pos + len > end) { error = true; return {}; }
    std::string result;
    if (huffman) {
        result = HpackHuffman::decode(pos, static_cast<size_t>(len));
    } else {
        result.assign(reinterpret_cast<const char*>(pos), static_cast<size_t>(len));
    }
    pos += len;
    return result;
}

std::vector<HpackHeaderField> HpackDecoder::decode(const uint8_t* data, size_t len, bool& error) {
    std::vector<HpackHeaderField> headers;
    error = false;
    const uint8_t* pos = data;
    const uint8_t* end = data + len;

    while (pos < end) {
        uint8_t byte = *pos;

        if (byte & 0x80) {
            // Indexed Header Field — integer encoded in the same byte's 7-bit prefix
            uint64_t idx = byte & 0x7F;
            ++pos;
            // If idx == 0x7F (mask value), there are continuation bytes
            if (idx == 0x7F) {
                idx += decodeInteger(pos, end, 0);  // read remaining with 0-bit prefix
            }
            if (idx == 0) { error = true; break; }
            if (idx <= HpackStaticTable::SIZE) {
                headers.push_back(HpackStaticTable::get(static_cast<size_t>(idx)));
            } else {
                auto* entry = dynamic_table_.get(static_cast<size_t>(idx));
                if (!entry) { error = true; break; }
                headers.push_back(*entry);
            }
        } else if (byte & 0x40) {
            // Literal with Incremental Indexing — 6-bit prefix in same byte
            uint64_t name_idx = byte & 0x3F;
            ++pos;
            if (name_idx == 0x3F) {
                name_idx += decodeInteger(pos, end, 0);
            }
            std::string name, value;
            if (name_idx == 0) {
                name = decodeString(pos, end, error);
                if (error) break;
            } else if (name_idx <= HpackStaticTable::SIZE) {
                name = HpackStaticTable::get(static_cast<size_t>(name_idx)).name;
            } else {
                auto* entry = dynamic_table_.get(static_cast<size_t>(name_idx));
                if (!entry) { error = true; break; }
                name = entry->name;
            }
            value = decodeString(pos, end, error);
            if (error) break;
            headers.push_back({name, value});
            dynamic_table_.add({name, value});
        } else if ((byte & 0xF0) == 0x00) {
            // Literal without Indexing or Never Indexed — 4-bit prefix in same byte
            uint64_t name_idx = byte & 0x0F;
            ++pos;
            if (name_idx == 0x0F) {
                name_idx += decodeInteger(pos, end, 0);
            }
            std::string name, value;
            if (name_idx == 0) {
                name = decodeString(pos, end, error);
                if (error) break;
            } else if (name_idx <= HpackStaticTable::SIZE) {
                name = HpackStaticTable::get(static_cast<size_t>(name_idx)).name;
            } else {
                auto* entry = dynamic_table_.get(static_cast<size_t>(name_idx));
                if (!entry) { error = true; break; }
                name = entry->name;
            }
            value = decodeString(pos, end, error);
            if (error) break;
            headers.push_back({name, value});
        } else if ((byte & 0xE0) == 0x20) {
            // Table Size Update — 5-bit prefix in same byte
            uint64_t table_size = byte & 0x1F;
            ++pos;
            if (table_size == 0x1F) {
                table_size += decodeInteger(pos, end, 0);
            }
            // The dynamic table size is tracked implicitly in setMaxSize
        } else {
            error = true;
            break;
        }
    }

    return headers;
}

// ═════════════════════════════════════════════════════════════════════
// Frame Header Utility
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::makeFrameHeader(
    uint32_t length, uint8_t type, uint8_t flags, uint32_t stream_id)
{
    std::vector<uint8_t> hdr(9);
    hdr[0] = static_cast<uint8_t>((length >> 16) & 0xFF);
    hdr[1] = static_cast<uint8_t>((length >> 8) & 0xFF);
    hdr[2] = static_cast<uint8_t>(length & 0xFF);
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = static_cast<uint8_t>((stream_id >> 24) & 0x7F);
    hdr[6] = static_cast<uint8_t>((stream_id >> 16) & 0xFF);
    hdr[7] = static_cast<uint8_t>((stream_id >> 8) & 0xFF);
    hdr[8] = static_cast<uint8_t>(stream_id & 0xFF);
    return hdr;
}

// ═════════════════════════════════════════════════════════════════════
// Http2Parser Constructor / Destructor
// ═════════════════════════════════════════════════════════════════════

Http2Parser::Http2Parser() {
    local_settings_[H2_SETTINGS_HEADER_TABLE_SIZE] = 4096;
    local_settings_[H2_SETTINGS_ENABLE_PUSH] = 0;
    local_settings_[H2_SETTINGS_MAX_CONCURRENT_STREAMS] = 100;
    local_settings_[H2_SETTINGS_INITIAL_WINDOW_SIZE] = 65535;
    local_settings_[H2_SETTINGS_MAX_FRAME_SIZE] = 16384;
    local_settings_[H2_SETTINGS_MAX_HEADER_LIST_SIZE] = 65535;

    // Default remote settings (what we assume the peer supports)
    remote_settings_[H2_SETTINGS_HEADER_TABLE_SIZE] = 4096;
    remote_settings_[H2_SETTINGS_ENABLE_PUSH] = 1;
    remote_settings_[H2_SETTINGS_MAX_CONCURRENT_STREAMS] = 100;
    remote_settings_[H2_SETTINGS_INITIAL_WINDOW_SIZE] = 65535;
    remote_settings_[H2_SETTINGS_MAX_FRAME_SIZE] = 16384;
    remote_settings_[H2_SETTINGS_MAX_HEADER_LIST_SIZE] = 65535;
    remote_max_concurrent_streams_ = 100;
}

Http2Parser::~Http2Parser() {}

// ═════════════════════════════════════════════════════════════════════
// Connection Management
// ═════════════════════════════════════════════════════════════════════

void Http2Parser::sendPreface() {
    if (preface_sent_) return;
    preface_sent_ = true;
    // Preface is handled externally (the caller sends PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
    // But we mark it as sent so feed() knows to expect the server's preface
}

bool Http2Parser::isConnected() const {
    return preface_sent_ && preface_received_;
}

// ═════════════════════════════════════════════════════════════════════
// Stream Management
// ═════════════════════════════════════════════════════════════════════

uint32_t Http2Parser::openStream() {
    if (goaway_sent_) return 0;
    if (activeStreamCount() >= remote_max_concurrent_streams_)
        return 0;

    uint32_t sid = next_stream_id_;
    next_stream_id_ += 2;  // Client-initiated streams are odd
    StreamData sd;
    sd.state = SS_IDLE;
    sd.recv_window = initial_window_size_;
    sd.send_window = initial_window_size_;
    streams_[sid] = sd;
    return sid;
}

bool Http2Parser::closeStream(uint32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return false;
    if (it->second.state == SS_OPEN ||
        it->second.state == SS_HALF_CLOSED_LOCAL ||
        it->second.state == SS_HALF_CLOSED_REMOTE) {
        if (active_stream_count_ > 0) --active_stream_count_;
    }
    it->second.state = SS_CLOSED;
    return true;
}

StreamState Http2Parser::getStreamState(uint32_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return SS_CLOSED;
    return it->second.state;
}

size_t Http2Parser::activeStreamCount() const {
    return active_stream_count_;
}

// ═════════════════════════════════════════════════════════════════════
// Stream State Machine (RFC 7540 Table 4)
// ═════════════════════════════════════════════════════════════════════

// Rows: current state (IDLE..CLOSED), Cols: events
// Value: new state index or SS_INVALID (255)
static const uint8_t kStateTransitions[7][10] = {
    // IDLE (0)
    { SS_OPEN, SS_OPEN, SS_CLOSED, SS_CLOSED, SS_CLOSED,
      SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_RESERVED_LOCAL, SS_RESERVED_REMOTE },
    // RESERVED_LOCAL (1)
    { SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_HALF_CLOSED_REMOTE,
      SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED },
    // RESERVED_REMOTE (2)
    { SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED,
      SS_HALF_CLOSED_LOCAL, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED },
    // OPEN (3)
    { SS_OPEN, SS_OPEN, SS_OPEN, SS_OPEN, SS_HALF_CLOSED_LOCAL,
      SS_HALF_CLOSED_REMOTE, SS_CLOSED, SS_CLOSED, SS_OPEN, SS_OPEN },
    // HALF_CLOSED_LOCAL (4)
    { SS_CLOSED, SS_HALF_CLOSED_LOCAL, SS_CLOSED, SS_HALF_CLOSED_LOCAL,
      SS_CLOSED, SS_HALF_CLOSED_REMOTE, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_HALF_CLOSED_LOCAL },
    // HALF_CLOSED_REMOTE (5)
    { SS_HALF_CLOSED_REMOTE, SS_CLOSED, SS_HALF_CLOSED_REMOTE, SS_CLOSED,
      SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_HALF_CLOSED_REMOTE, SS_CLOSED },
    // CLOSED (6)
    { SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED,
      SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED, SS_CLOSED }
};

StreamState Http2Parser::transitionState(StreamState current, StreamEvent event) {
    uint8_t row = static_cast<uint8_t>(current);
    uint8_t col = static_cast<uint8_t>(event);
    if (row >= 7 || col >= 10) return SS_INVALID;
    uint8_t new_state = kStateTransitions[row][col];
    if (new_state == SS_INVALID) return SS_INVALID;
    return static_cast<StreamState>(new_state);
}

bool Http2Parser::transitionStream(uint32_t stream_id, StreamEvent event) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return false;
    StreamState new_state = transitionState(it->second.state, event);
    if (new_state == SS_INVALID) return false;

    // Track active stream count (OPEN or HALF_CLOSED = active)
    auto isActive = [](StreamState s) {
        return s == SS_OPEN || s == SS_HALF_CLOSED_LOCAL || s == SS_HALF_CLOSED_REMOTE;
    };
    bool was_active = isActive(it->second.state);
    bool now_active = isActive(new_state);
    if (was_active && !now_active) {
        if (active_stream_count_ > 0) --active_stream_count_;
    } else if (!was_active && now_active) {
        ++active_stream_count_;
    }

    it->second.state = new_state;
    if (new_state == SS_CLOSED) {
        removePriorityNode(stream_id);
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// Flow Control
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::consumeConnectionWindow(uint32_t size) {
    if (connection_window_ < size) return false;
    connection_window_ -= size;
    return true;
}

bool Http2Parser::consumeStreamWindow(uint32_t stream_id, uint32_t size) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return false;
    if (it->second.recv_window < size) return false;
    it->second.recv_window -= size;
    connection_window_ -= size;
    return true;
}

void Http2Parser::updateConnectionWindow(uint32_t increment) {
    if (increment == 0) return;
    uint64_t new_window = static_cast<uint64_t>(connection_window_) + increment;
    if (new_window > 0x7FFFFFFF) return;  // RFC 7540 §6.9.1
    connection_window_ = static_cast<uint32_t>(new_window);
}

void Http2Parser::updateStreamWindow(uint32_t stream_id, uint32_t increment) {
    if (increment == 0) return;
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    uint64_t new_window = static_cast<uint64_t>(it->second.recv_window) + increment;
    if (new_window > 0x7FFFFFFF) return;
    it->second.recv_window = static_cast<uint32_t>(new_window);
}

uint32_t Http2Parser::streamWindow(uint32_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return 0;
    return it->second.recv_window;
}

void Http2Parser::setBdpEstimate(uint32_t bdp_bytes) {
    bdp_estimate_ = bdp_bytes;
    bdp_autotune_enabled_ = true;
    uint32_t target = std::max(65535u, std::min(bdp_bytes * 2, 524288u));  // max 512KB
    if (target > initial_window_size_) {
        uint32_t increment = target - initial_window_size_;
        initial_window_size_ = target;
        // The caller should send a WINDOW_UPDATE with this increment
        connection_window_delta_ += increment;
    }
}

// ═════════════════════════════════════════════════════════════════════
// Priority Tree
// ═════════════════════════════════════════════════════════════════════

PriorityNode* Http2Parser::findPriorityNode(uint32_t stream_id) {
    auto it = priority_nodes_.find(stream_id);
    if (it == priority_nodes_.end()) return nullptr;
    return &it->second;
}

void Http2Parser::addPriorityNode(uint32_t stream_id, uint32_t parent_id,
                                   int32_t weight, bool exclusive) {
    // Remove existing node first
    removePriorityNode(stream_id);

    PriorityNode node;
    node.stream_id = stream_id;
    node.parent_id = parent_id;
    node.weight = weight;
    node.exclusive = exclusive;

    // Handle exclusive: reparent siblings
    if (exclusive) {
        auto* parent = findPriorityNode(parent_id);
        if (parent) {
            for (uint32_t child : parent->children) {
                if (child != stream_id) {
                    node.children.push_back(child);
                }
            }
            parent->children.clear();
            parent->children.push_back(stream_id);
        }
    } else {
        auto* parent = findPriorityNode(parent_id);
        if (parent) {
            parent->children.push_back(stream_id);
        }
    }

    priority_nodes_[stream_id] = node;
}

void Http2Parser::removePriorityNode(uint32_t stream_id) {
    auto it = priority_nodes_.find(stream_id);
    if (it == priority_nodes_.end()) return;

    // Reparent children to parent
    PriorityNode& node = it->second;
    auto* parent = findPriorityNode(node.parent_id);
    if (parent && node.parent_id != ROOT_STREAM_ID) {
        for (uint32_t child : node.children) {
            parent->children.push_back(child);
            auto* cp = findPriorityNode(child);
            if (cp) cp->parent_id = node.parent_id;
        }
    }
    // Remove from parent's children list
    if (parent) {
        parent->children.erase(
            std::remove(parent->children.begin(), parent->children.end(), stream_id),
            parent->children.end());
    }

    priority_nodes_.erase(it);
}

// ═════════════════════════════════════════════════════════════════════
// Header Validation (RFC 7540 Section 8)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::isConnectionSpecific(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) lower.push_back(static_cast<char>(std::tolower(c)));
    return lower == "connection" || lower == "keep-alive" ||
           lower == "proxy-connection" || lower == "transfer-encoding" ||
           lower == "upgrade";
}

bool Http2Parser::validateRequestHeaders(const std::vector<HpackHeaderField>& headers) {
    bool has_method = false, has_path = false, has_scheme = false;
    bool pseudo_done = false;

    for (const auto& h : headers) {
        if (h.name.empty()) return false;
        bool is_pseudo = !h.name.empty() && h.name[0] == ':';
        if (is_pseudo && pseudo_done) return false;
        if (!is_pseudo) pseudo_done = true;

        if (isConnectionSpecific(h.name)) return false;

        if (h.name == ":method") has_method = true;
        else if (h.name == ":path") has_path = true;
        else if (h.name == ":scheme") has_scheme = true;
    }

    return has_method && has_path && has_scheme;
}

bool Http2Parser::validateResponseHeaders(const std::vector<HpackHeaderField>& headers) {
    bool has_status = false;
    bool pseudo_done = false;

    for (const auto& h : headers) {
        if (h.name.empty()) return false;
        bool is_pseudo = h.name[0] == ':';
        if (is_pseudo && pseudo_done) return false;
        if (!is_pseudo) pseudo_done = true;

        if (isConnectionSpecific(h.name)) return false;

        if (h.name == ":status") {
            has_status = true;
            if (h.value.size() != 3) return false;
            for (char c : h.value) if (c < '0' || c > '9') return false;
        }
    }

    return has_status;
}

// ═════════════════════════════════════════════════════════════════════
// Error Helper
// ═════════════════════════════════════════════════════════════════════

void Http2Parser::emitFrameError(const std::string& msg) {
    if (on_frame_error_) on_frame_error_(msg);
}

// ═════════════════════════════════════════════════════════════════════
// Feed (Main Entry Point)
// ═════════════════════════════════════════════════════════════════════

size_t Http2Parser::feed(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0;

    // Check for HTTP/2 preface
    static const uint8_t kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static constexpr size_t kPrefaceLen = 24;

    if (!preface_received_ && len >= kPrefaceLen) {
        if (std::memcmp(data, kPreface, kPrefaceLen) == 0) {
            preface_received_ = true;
            data += kPrefaceLen;
            len -= kPrefaceLen;
            if (len == 0) return kPrefaceLen;
        }
    }

    // Add to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    size_t total_consumed = len;
    size_t processed = 0;

    while (true) {
        if (buffer_.size() < processed + 9) break;

        // Parse frame header
        uint32_t flen = (static_cast<uint32_t>(buffer_[processed]) << 16) |
                        (static_cast<uint32_t>(buffer_[processed + 1]) << 8) |
                        static_cast<uint32_t>(buffer_[processed + 2]);
        uint8_t ftype = buffer_[processed + 3];
        uint8_t fflags = buffer_[processed + 4];
        uint32_t sid = (static_cast<uint32_t>(buffer_[processed + 5] & 0x7F) << 24) |
                       (static_cast<uint32_t>(buffer_[processed + 6]) << 16) |
                       (static_cast<uint32_t>(buffer_[processed + 7]) << 8) |
                       static_cast<uint32_t>(buffer_[processed + 8]);

        if (buffer_.size() < processed + 9 + flen) break;

        Http2FrameHeader hdr{flen, ftype, fflags, sid};
        const uint8_t* payload = buffer_.data() + processed + 9;

        if (!processFrame(hdr, payload)) {
            emitFrameError("Frame processing failed");
            break;
        }

        processed += 9 + flen;
    }

    if (processed > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(processed));
    }

    return total_consumed;
}

// ═════════════════════════════════════════════════════════════════════
// Frame Dispatch
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    // Validate frame size
    if (hdr.length > remote_max_frame_size_) {
        emitFrameError("Frame exceeds max frame size");
        return false;
    }

    switch (hdr.type) {
        case H2_DATA:             return processDataFrame(hdr, payload);
        case H2_HEADERS:          return processHeadersFrame(hdr, payload);
        case H2_PRIORITY:         return processPriorityFrame(hdr, payload);
        case H2_RST_STREAM:       return processRstStreamFrame(hdr, payload);
        case H2_SETTINGS:         return processSettingsFrame(hdr, payload);
        case H2_PUSH_PROMISE:     return processPushPromiseFrame(hdr, payload);
        case H2_PING:             return processPingFrame(hdr, payload);
        case H2_GOAWAY:           return processGoawayFrame(hdr, payload);
        case H2_WINDOW_UPDATE:    return processWindowUpdateFrame(hdr, payload);
        case H2_CONTINUATION:     return processContinuationFrame(hdr, payload);
        default:
            emitFrameError("Unknown frame type");
            return true;  // Ignore unknown frames per RFC 7540
    }
}

// ═════════════════════════════════════════════════════════════════════
// DATA Frame (0x00)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processDataFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id == 0) {
        emitFrameError("DATA frame with stream_id=0");
        return false;
    }

    // Handle padding
    uint32_t offset = 0;
    uint32_t data_len = hdr.length;
    if (hdr.flags & H2_FLAG_PADDED) {
        if (hdr.length == 0) return false;
        uint8_t pad_len = payload[0];
        offset = 1;
        if (1 + pad_len > hdr.length) {
            emitFrameError("DATA padding exceeds frame length");
            return false;
        }
        data_len = hdr.length - 1 - pad_len;
    }

    // Verify stream exists and is in valid state
    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end()) {
        // Create the stream if we receive data first (server push, etc.)
        StreamData sd;
        sd.state = SS_OPEN;
        streams_[hdr.stream_id] = sd;
        it = streams_.find(hdr.stream_id);
    }

    if (it->second.state != SS_OPEN && it->second.state != SS_HALF_CLOSED_LOCAL) {
        emitFrameError("DATA on non-open stream");
        return false;
    }

    // Flow control: consume window
    if (!consumeConnectionWindow(data_len)) {
        emitFrameError("Connection flow control exceeded");
        return false;
    }
    if (!consumeStreamWindow(hdr.stream_id, data_len)) {
        emitFrameError("Stream flow control exceeded");
        return false;
    }

    it->second.recv_data_total += data_len;

    bool end_stream = (hdr.flags & H2_FLAG_END_STREAM) != 0;
    if (end_stream) {
        transitionStream(hdr.stream_id, SE_RECV_END_STREAM);
    }

    // Fire data callback
    if (on_data_ && data_len > 0) {
        on_data_(hdr.stream_id, payload + offset, data_len, end_stream);
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// HEADERS Frame (0x01)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processHeadersFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id == 0) {
        emitFrameError("HEADERS frame with stream_id=0");
        return false;
    }

    // Parse optional fields
    uint32_t offset = 0;
    if (hdr.flags & H2_FLAG_PADDED) {
        if (hdr.length == 0) return false;
        offset = 1 + payload[0];
        if (offset > hdr.length) return false;
    }

    uint32_t priority_dep = 0;
    int32_t weight = 16;  // default
    bool exclusive = false;
    if (hdr.flags & H2_FLAG_PRIORITY) {
        if (offset + 5 > hdr.length) return false;
        exclusive = (payload[offset] & 0x80) != 0;
        priority_dep = (static_cast<uint32_t>(payload[offset] & 0x7F) << 24) |
                       (static_cast<uint32_t>(payload[offset + 1]) << 16) |
                       (static_cast<uint32_t>(payload[offset + 2]) << 8) |
                       static_cast<uint32_t>(payload[offset + 3]);
        weight = static_cast<int32_t>(payload[offset + 4]) + 1;
        offset += 5;
    }

    uint32_t header_block_offset = offset;
    uint32_t header_block_len = hdr.length - offset;

    // Create or find stream
    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end()) {
        StreamData sd;
        sd.state = SS_IDLE;
        streams_[hdr.stream_id] = sd;
        it = streams_.find(hdr.stream_id);
    }

    if (hdr.flags & H2_FLAG_PRIORITY) {
        addPriorityNode(hdr.stream_id, priority_dep, weight, exclusive);
    }

    bool end_headers = (hdr.flags & H2_FLAG_END_HEADERS) != 0;
    bool end_stream = (hdr.flags & H2_FLAG_END_STREAM) != 0;

    if (end_headers) {
        // Decode HPACK block
        bool hpack_error = false;
        auto headers = decoder_.decode(payload + header_block_offset,
                                        header_block_len, hpack_error);
        if (hpack_error) {
            emitFrameError("HPACK decode error in HEADERS");
            return false;
        }

        // Validate
        bool is_request = (hdr.stream_id % 2 == 1);  // client-initiated
        if (is_request && !validateRequestHeaders(headers)) {
            emitFrameError("Invalid request headers");
            return false;
        }
        if (!is_request && !validateResponseHeaders(headers)) {
            emitFrameError("Invalid response headers");
            return false;
        }

        // Transition state
        transitionStream(hdr.stream_id, hdr.stream_id % 2 == 1 ? SE_SEND_HEADERS : SE_RECV_HEADERS);
        if (end_stream) {
            transitionStream(hdr.stream_id, SE_RECV_END_STREAM);
        }

        if (on_headers_) {
            on_headers_(hdr.stream_id, headers, end_stream);
        }
    } else {
        // Buffer HEADERS fragment for continuation
        it->second.header_fragment.assign(
            payload + header_block_offset,
            payload + header_block_offset + header_block_len);
        it->second.headers_started = true;
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// PRIORITY Frame (0x02)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processPriorityFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id == 0) {
        emitFrameError("PRIORITY frame with stream_id=0");
        return false;
    }
    if (hdr.length != 5) {
        emitFrameError("PRIORITY frame must be 5 bytes");
        return false;
    }

    bool exclusive = (payload[0] & 0x80) != 0;
    uint32_t dep_id = (static_cast<uint32_t>(payload[0] & 0x7F) << 24) |
                      (static_cast<uint32_t>(payload[1]) << 16) |
                      (static_cast<uint32_t>(payload[2]) << 8) |
                      static_cast<uint32_t>(payload[3]);
    int32_t weight = static_cast<int32_t>(payload[4]) + 1;

    if (dep_id == hdr.stream_id) {
        emitFrameError("PRIORITY self-dependency");
        return false;
    }

    addPriorityNode(hdr.stream_id, dep_id, weight, exclusive);
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// RST_STREAM Frame (0x03)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processRstStreamFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id == 0) {
        emitFrameError("RST_STREAM frame with stream_id=0");
        return false;
    }
    if (hdr.length != 4) {
        emitFrameError("RST_STREAM frame must be 4 bytes");
        return false;
    }

    uint32_t error_code = (static_cast<uint32_t>(payload[0]) << 24) |
                          (static_cast<uint32_t>(payload[1]) << 16) |
                          (static_cast<uint32_t>(payload[2]) << 8) |
                          static_cast<uint32_t>(payload[3]);

    transitionStream(hdr.stream_id, SE_RECV_RST_STREAM);

    if (on_stream_reset_) {
        on_stream_reset_(hdr.stream_id, static_cast<Http2Error>(error_code));
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// SETTINGS Frame (0x04)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processSettingsFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id != 0) {
        emitFrameError("SETTINGS frame with non-zero stream_id");
        return false;
    }

    // ACK flag
    if (hdr.flags & H2_FLAG_ACK) {
        if (hdr.length != 0) {
            emitFrameError("SETTINGS ACK must have empty payload");
            return false;
        }
        return true;
    }

    if (hdr.length % 6 != 0) {
        emitFrameError("SETTINGS payload must be multiple of 6");
        return false;
    }

    std::map<uint16_t, uint32_t> new_settings;
    for (uint32_t i = 0; i < hdr.length; i += 6) {
        uint16_t id = (static_cast<uint16_t>(payload[i]) << 8) |
                       static_cast<uint16_t>(payload[i + 1]);
        uint32_t value = (static_cast<uint32_t>(payload[i + 2]) << 24) |
                         (static_cast<uint32_t>(payload[i + 3]) << 16) |
                         (static_cast<uint32_t>(payload[i + 4]) << 8) |
                         static_cast<uint32_t>(payload[i + 5]);

        // Validate settings
        if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE && value > 0x7FFFFFFF) {
            emitFrameError("SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1");
            return false;
        }
        if (id == H2_SETTINGS_MAX_FRAME_SIZE && (value < 16384 || value > 16777215)) {
            emitFrameError("SETTINGS_MAX_FRAME_SIZE out of range");
            return false;
        }
        if (id == H2_SETTINGS_ENABLE_PUSH && value > 1) {
            emitFrameError("SETTINGS_ENABLE_PUSH must be 0 or 1");
            return false;
        }

        new_settings[id] = value;
    }

    // Apply settings
    for (const auto& [id, value] : new_settings) {
        remote_settings_[id] = value;
        if (id == H2_SETTINGS_HEADER_TABLE_SIZE) {
            decoder_.setTableSize(value);
        }
        if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE) {
            int32_t delta = static_cast<int32_t>(value) - static_cast<int32_t>(initial_window_size_);
            initial_window_size_ = value;
            // Update all stream windows
            for (auto& [sid, sd] : streams_) {
                int64_t new_win = static_cast<int64_t>(sd.send_window) + delta;
                if (new_win > 0x7FFFFFFF) new_win = 0x7FFFFFFF;
                sd.send_window = static_cast<uint32_t>(new_win);
            }
        }
        if (id == H2_SETTINGS_MAX_FRAME_SIZE) {
            remote_max_frame_size_ = value;
        }
    }

    if (on_settings_) {
        on_settings_(new_settings);
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// PUSH_PROMISE Frame (0x05)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processPushPromiseFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    // Push is disabled by default in our settings; just ignore
    (void)hdr;
    (void)payload;
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// PING Frame (0x06)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processPingFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id != 0) {
        emitFrameError("PING frame with non-zero stream_id");
        return false;
    }
    if (hdr.length != 8) {
        emitFrameError("PING frame must be 8 bytes");
        return false;
    }

    // Automatically send PING ACK (we don't auto-respond here; caller's callback does)
    // If not ACK, nothing to process
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// GOAWAY Frame (0x07)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processGoawayFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id != 0) {
        emitFrameError("GOAWAY frame with non-zero stream_id");
        return false;
    }
    if (hdr.length < 8) {
        emitFrameError("GOAWAY frame too short");
        return false;
    }

    uint32_t last_id = (static_cast<uint32_t>(payload[0]) << 24) |
                       (static_cast<uint32_t>(payload[1]) << 16) |
                       (static_cast<uint32_t>(payload[2]) << 8) |
                       static_cast<uint32_t>(payload[3]);
    uint32_t err_code = (static_cast<uint32_t>(payload[4]) << 24) |
                        (static_cast<uint32_t>(payload[5]) << 16) |
                        (static_cast<uint32_t>(payload[6]) << 8) |
                        static_cast<uint32_t>(payload[7]);

    goaway_received_ = true;
    goaway_last_stream_id_ = last_id;

    std::vector<uint8_t> debug;
    if (hdr.length > 8) {
        debug.assign(payload + 8, payload + hdr.length);
    }

    if (on_goaway_) {
        on_goaway_(last_id, static_cast<Http2Error>(err_code), debug);
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// WINDOW_UPDATE Frame (0x08)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processWindowUpdateFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.length != 4) {
        emitFrameError("WINDOW_UPDATE frame must be 4 bytes");
        return false;
    }

    uint32_t increment = (static_cast<uint32_t>(payload[0]) << 24) |
                         (static_cast<uint32_t>(payload[1]) << 16) |
                         (static_cast<uint32_t>(payload[2]) << 8) |
                         static_cast<uint32_t>(payload[3]);

    if (increment == 0) {
        emitFrameError("WINDOW_UPDATE increment must not be 0");
        return false;
    }

    if (hdr.stream_id == 0) {
        updateConnectionWindow(increment);
    } else {
        updateStreamWindow(hdr.stream_id, increment);
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// CONTINUATION Frame (0x09)
// ═════════════════════════════════════════════════════════════════════

bool Http2Parser::processContinuationFrame(const Http2FrameHeader& hdr, const uint8_t* payload) {
    if (hdr.stream_id == 0) {
        emitFrameError("CONTINUATION frame with stream_id=0");
        return false;
    }

    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end() || !it->second.headers_started) {
        emitFrameError("CONTINUATION without preceding HEADERS");
        return false;
    }

    // Append to header fragment
    it->second.header_fragment.insert(
        it->second.header_fragment.end(), payload, payload + hdr.length);

    bool end_headers = (hdr.flags & H2_FLAG_END_HEADERS) != 0;
    if (end_headers) {
        // Decode accumulated HPACK block
        bool hpack_error = false;
        auto headers = decoder_.decode(
            it->second.header_fragment.data(),
            it->second.header_fragment.size(), hpack_error);
        if (hpack_error) {
            emitFrameError("HPACK decode error in CONTINUATION");
            return false;
        }

        // Validate
        bool is_request = (hdr.stream_id % 2 == 1);
        if (is_request && !validateRequestHeaders(headers)) {
            emitFrameError("Invalid request headers");
            return false;
        }
        if (!is_request && !validateResponseHeaders(headers)) {
            emitFrameError("Invalid response headers");
            return false;
        }

        // Store decoded headers
        it->second.decoded_headers = headers;
        it->second.headers_complete = true;
        it->second.header_fragment.clear();

        if (on_headers_) {
            on_headers_(hdr.stream_id, headers, false);
        }
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: Settings
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeSettings(
    const std::map<uint16_t, uint32_t>& settings)
{
    std::vector<uint8_t> payload;
    for (const auto& [id, value] : settings) {
        payload.push_back(static_cast<uint8_t>(id >> 8));
        payload.push_back(static_cast<uint8_t>(id & 0xFF));
        payload.push_back(static_cast<uint8_t>(value >> 24));
        payload.push_back(static_cast<uint8_t>(value >> 16));
        payload.push_back(static_cast<uint8_t>(value >> 8));
        payload.push_back(static_cast<uint8_t>(value));
    }

    auto frame = makeFrameHeader(static_cast<uint32_t>(payload.size()),
                                  H2_SETTINGS, 0x00, 0);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::vector<uint8_t> Http2Parser::serializeSettingsAck() {
    return makeFrameHeader(0, H2_SETTINGS, H2_FLAG_ACK, 0);
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: HEADERS
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeHeaders(uint32_t stream_id,
    const std::vector<HpackHeaderField>& headers, bool end_stream)
{
    bool hpack_error = false;
    auto hpack_block = encoder_.encode(headers, hpack_error);
    if (hpack_error) return {};

    uint8_t flags = H2_FLAG_END_HEADERS;
    if (end_stream) flags |= H2_FLAG_END_STREAM;

    auto frame = makeFrameHeader(static_cast<uint32_t>(hpack_block.size()),
                                  H2_HEADERS, flags, stream_id);
    frame.insert(frame.end(), hpack_block.begin(), hpack_block.end());
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: DATA
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeData(uint32_t stream_id,
    const uint8_t* data, size_t len, bool end_stream)
{
    uint8_t flags = end_stream ? H2_FLAG_END_STREAM : 0x00;
    auto frame = makeFrameHeader(static_cast<uint32_t>(len),
                                  H2_DATA, flags, stream_id);
    frame.insert(frame.end(), data, data + len);
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: RST_STREAM
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeRstStream(uint32_t stream_id, Http2Error error) {
    std::vector<uint8_t> payload(4);
    uint32_t ec = static_cast<uint32_t>(error);
    payload[0] = static_cast<uint8_t>(ec >> 24);
    payload[1] = static_cast<uint8_t>(ec >> 16);
    payload[2] = static_cast<uint8_t>(ec >> 8);
    payload[3] = static_cast<uint8_t>(ec);

    auto frame = makeFrameHeader(4, H2_RST_STREAM, 0x00, stream_id);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: PING
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializePing(const uint8_t data[8]) {
    auto frame = makeFrameHeader(8, H2_PING, 0x00, 0);
    frame.insert(frame.end(), data, data + 8);
    return frame;
}

std::vector<uint8_t> Http2Parser::serializePingAck(const uint8_t data[8]) {
    auto frame = makeFrameHeader(8, H2_PING, H2_FLAG_ACK, 0);
    frame.insert(frame.end(), data, data + 8);
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: GOAWAY
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeGoaway(uint32_t last_stream_id, Http2Error error) {
    std::vector<uint8_t> payload(8);
    payload[0] = static_cast<uint8_t>(last_stream_id >> 24);
    payload[1] = static_cast<uint8_t>(last_stream_id >> 16);
    payload[2] = static_cast<uint8_t>(last_stream_id >> 8);
    payload[3] = static_cast<uint8_t>(last_stream_id);
    uint32_t ec = static_cast<uint32_t>(error);
    payload[4] = static_cast<uint8_t>(ec >> 24);
    payload[5] = static_cast<uint8_t>(ec >> 16);
    payload[6] = static_cast<uint8_t>(ec >> 8);
    payload[7] = static_cast<uint8_t>(ec);

    auto frame = makeFrameHeader(8, H2_GOAWAY, 0x00, 0);
    frame.insert(frame.end(), payload.begin(), payload.end());

    goaway_sent_ = true;
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: WINDOW_UPDATE
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializeWindowUpdate(uint32_t stream_id, uint32_t increment) {
    std::vector<uint8_t> payload(4);
    payload[0] = static_cast<uint8_t>(increment >> 24);
    payload[1] = static_cast<uint8_t>(increment >> 16);
    payload[2] = static_cast<uint8_t>(increment >> 8);
    payload[3] = static_cast<uint8_t>(increment);

    auto frame = makeFrameHeader(4, H2_WINDOW_UPDATE, 0x00, stream_id);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// ═════════════════════════════════════════════════════════════════════
// Serialization: PRIORITY
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> Http2Parser::serializePriority(uint32_t stream_id,
    uint32_t parent_id, int32_t weight, bool exclusive)
{
    std::vector<uint8_t> payload(5);
    if (exclusive) {
        payload[0] = static_cast<uint8_t>((parent_id >> 24) | 0x80);
    } else {
        payload[0] = static_cast<uint8_t>(parent_id >> 24);
    }
    payload[1] = static_cast<uint8_t>(parent_id >> 16);
    payload[2] = static_cast<uint8_t>(parent_id >> 8);
    payload[3] = static_cast<uint8_t>(parent_id);
    payload[4] = static_cast<uint8_t>(weight - 1);

    auto frame = makeFrameHeader(5, H2_PRIORITY, 0x00, stream_id);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}
