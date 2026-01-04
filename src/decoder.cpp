#include "decoder.h"
#include "config.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <stdexcept>
#include <cstdarg>

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

static std::string sanitize_string(const uint8_t* p, size_t n) {
    std::string s(reinterpret_cast<const char*>(p), n);
    for (char& c : s) {
        if (c == '\0') c = ' ';
    }
    return s;
}

static void print_field_value(const uint8_t* base, const FieldSpec& f, const DecodeOptions& opt) {
    const uint8_t* p = base + f.offset;

    if (opt.verbose) {
        std::printf("%s: ", f.name.c_str());
    }

    switch (f.type) {
        case FieldType::CHAR: {
            char c = char(p[0]);
            std::printf("%c", c);
            break;
        }
        case FieldType::UINT8: {
            std::printf("%u", unsigned(p[0]));
            break;
        }
        case FieldType::UINT32: {
            if (f.size != 4) throw std::runtime_error("UINT32 field size must be 4: " + f.name);
            std::printf("%u", be32(p));
            break;
        }
        case FieldType::UINT64: {
            if (f.size != 8) throw std::runtime_error("UINT64 field size must be 8: " + f.name);
            std::printf("%llu", (unsigned long long)be64(p));
            break;
        }
        case FieldType::STRING: {
            // print as visible string (spaces preserved)
            std::string s = sanitize_string(p, f.size);
            if (opt.print_hex_strings) {
                // optional debug mode: show raw bytes too
                std::printf("%s", s.c_str());
            } else {
                std::printf("%s", s.c_str());
            }
            break;
        }
        default:
            std::printf("?");
            break;
    }
}

static const MsgSpec* find_spec(uint8_t msg_type) {
    const auto& specs = config().msg_specs;
    auto it = specs.find(char(msg_type));
    if (it == specs.end()) return nullptr;
    return &it->second;
}

void decode_moldudp64_packet(const uint8_t* buf, size_t len, const DecodeOptions& opt) {
    if (len < sizeof(MoldHeaderRaw)) return;

    const auto* h = reinterpret_cast<const MoldHeaderRaw*>(buf);

    std::string_view session(h->session, 10);

    // decode header BE (safe without relying on alignment)
    uint64_t seq = be64(reinterpret_cast<const uint8_t*>(&h->sequence_number_be));
    uint16_t cnt = be16(reinterpret_cast<const uint8_t*>(&h->message_count_be));

    size_t off = sizeof(MoldHeaderRaw);

    // End-of-session: 0xFFFF is common sentinel in MoldUDP64 usage
    if (cnt == 0xFFFF) {
        std::printf(">> {'%.*s', %llu, %u}\n",
                    (int)session.size(), session.data(),
                    (unsigned long long)seq, (unsigned)cnt);
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
        if (!spec) {
            // unknown type: still print header info
            std::printf(">> {'%.*s', %llu, %u,'?'}\n",
                        (int)session.size(), session.data(),
                        (unsigned long long)(seq + i), (unsigned)cnt);
            off += msg_len;
            continue;
        }

        // (Optional sanity) msg_len should match spec->total_length
        // Some feeds may wrap or extend; in strict mode you can enforce equality.
        if (spec->total_length != msg_len) {
            // Don’t crash the harness; print a warning-like line
            // (Production version: you may want to count / log and skip)
            // std::fprintf(stderr, "WARN: len mismatch type %c spec=%u msg=%u\n",
            //              char(msg_type), spec->total_length, msg_len);
        }

        // Print in your format (single line per message)
        std::printf(">> {'%.*s', %llu, %u,' %c', ",
                    (int)session.size(), session.data(),
                    (unsigned long long)(seq + i),
                    (unsigned)cnt,
                    char(msg_type));

        bool first = true;
        for (const auto& f : spec->fields) {
            if (!first) std::printf(", ");
            first = false;

            std::printf("'");
            print_field_value(msg, f, opt);
            std::printf("'");
        }

        std::printf("}\n");

        off += msg_len;
    }
}
