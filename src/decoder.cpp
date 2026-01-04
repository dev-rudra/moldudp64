#include "decoder.h"
#include "config.h"

#include <cstdio>
#include <cstring>
#include <string_view>
#include <stdexcept>
#include <cstdarg>
#include <unistd.h>     // write()

#pragma pack(push, 1)
struct MoldHeaderRaw {
    char     session[10];
    uint64_t sequence_number_be;
    uint16_t message_count_be;
};
#pragma pack(pop)

static inline uint16_t be16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
static inline uint64_t be64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48) | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32) |
           (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16) | (uint64_t(p[6]) << 8)  | uint64_t(p[7]);
}

// No allocations: print fixed strings directly with precision, replace '\0' with space while copying into output.
static inline size_t append_sanitized_fixed(char* out, size_t cap, const uint8_t* p, size_t n) {
    size_t w = 0;
    while (w < n && w < cap) {
        char c = (char)p[w];
        out[w] = (c == '\0') ? ' ' : c;
        ++w;
    }
    return w;
}

static inline int append(char*& cur, char* end, const char* fmt, ...) {
    if (cur >= end) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(cur, (size_t)(end - cur), fmt, ap);
    va_end(ap);
    if (n <= 0) return 0;
    if (cur + n > end) { cur = end; return 0; }
    cur += n;
    return n;
}

static const MsgSpec* find_spec(uint8_t msg_type) {
    const auto& specs = config().msg_specs;
    auto it = specs.find(char(msg_type));
    if (it == specs.end()) return nullptr;
    return &it->second;
}

static inline void append_field(char*& cur, char* end, const uint8_t* msg_base, const FieldSpec& f, const DecodeOptions& opt) {
    const uint8_t* p = msg_base + f.offset;

    // leading quote already printed by caller
    if (opt.verbose) {
        append(cur, end, "%s: ", f.name.c_str());
    }

    switch (f.type) {
        case FieldType::CHAR:
            append(cur, end, "%c", (char)p[0]);
            break;
        case FieldType::UINT8:
            append(cur, end, "%u", (unsigned)p[0]);
            break;
        case FieldType::UINT32:
            if (f.size != 4) throw std::runtime_error("UINT32 size != 4 for field: " + f.name);
            append(cur, end, "%u", be32(p));
            break;
        case FieldType::UINT64:
            if (f.size != 8) throw std::runtime_error("UINT64 size != 8 for field: " + f.name);
            append(cur, end, "%llu", (unsigned long long)be64(p));
            break;
        case FieldType::STRING: {
            // write raw fixed-length bytes into output (sanitized)
            // avoid printf("%.*s") because it stops at '\0'
            size_t cap = (size_t)(end - cur);
            size_t wrote = append_sanitized_fixed(cur, cap, p, f.size);
            cur += wrote;
            break;
        }
        default:
            append(cur, end, "?");
            break;
    }
}

void decode_moldudp64_packet(const uint8_t* buf, size_t len, const DecodeOptions& opt) {
    if (len < sizeof(MoldHeaderRaw)) return;

    const auto* h = reinterpret_cast<const MoldHeaderRaw*>(buf);
    std::string_view session(h->session, 10);

    uint64_t seq = be64(reinterpret_cast<const uint8_t*>(&h->sequence_number_be));
    uint16_t cnt = be16(reinterpret_cast<const uint8_t*>(&h->message_count_be));

    size_t off = sizeof(MoldHeaderRaw);

    if (cnt == 0xFFFF) {
        char out[256];
        char* cur = out;
        char* end = out + sizeof(out);
        append(cur, end, ">> {'%.*s', %llu, %u}\n",
               (int)session.size(), session.data(),
               (unsigned long long)seq, (unsigned)cnt);
        (void)!write(1, out, (size_t)(cur - out));
        return;
    }

    for (uint16_t i = 0; i < cnt; ++i) {
        if (off + 2 > len) break;

        uint16_t msg_len = be16(buf + off);
        off += 2;
        if (off + msg_len > len) break;
        if (msg_len == 0) continue;

        const uint8_t* msg = buf + off;
        uint8_t msg_type = msg[0];

        const MsgSpec* spec = find_spec(msg_type);

        // Build one full line then single write()
        char out[4096];
        char* cur = out;
        char* end = out + sizeof(out);

        // Header portion like your style:
        // >> {'SESSION', SEQ, COUNT,'T',
        append(cur, end, ">> {'%.*s', %llu, %u,'%c'",
               (int)session.size(), session.data(),
               (unsigned long long)(seq + i),
               (unsigned)cnt,
               (char)msg_type);

        if (!spec) {
            append(cur, end, "}\n");
            (void)!write(1, out, (size_t)(cur - out));
            off += msg_len;
            continue;
        }

        // Print each field as: , 'value'
        for (size_t fi = 0; fi < spec->fields.size(); ++fi) {
            append(cur, end, ", '");
            append_field(cur, end, msg, spec->fields[fi], opt);
            append(cur, end, "'");
        }

        append(cur, end, "}\n");
        (void)!write(1, out, (size_t)(cur - out));

        off += msg_len;
    }
}
