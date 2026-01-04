#include "config.h"
#include "decoder.h"

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

// ---------- helpers: big-endian writers ----------
static void push_be16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(uint8_t((v >> 8) & 0xFF));
    b.push_back(uint8_t(v & 0xFF));
}
static void push_be32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(uint8_t((v >> 24) & 0xFF));
    b.push_back(uint8_t((v >> 16) & 0xFF));
    b.push_back(uint8_t((v >> 8) & 0xFF));
    b.push_back(uint8_t(v & 0xFF));
}
static void push_be64(std::vector<uint8_t>& b, uint64_t v) {
    b.push_back(uint8_t((v >> 56) & 0xFF));
    b.push_back(uint8_t((v >> 48) & 0xFF));
    b.push_back(uint8_t((v >> 40) & 0xFF));
    b.push_back(uint8_t((v >> 32) & 0xFF));
    b.push_back(uint8_t((v >> 24) & 0xFF));
    b.push_back(uint8_t((v >> 16) & 0xFF));
    b.push_back(uint8_t((v >> 8) & 0xFF));
    b.push_back(uint8_t(v & 0xFF));
}
static void push_str_fixed(std::vector<uint8_t>& b, const char* s, size_t n) {
    size_t sl = std::strlen(s);
    for (size_t i = 0; i < n; ++i) {
        char c = (i < sl) ? s[i] : ' ';
        b.push_back(uint8_t(c));
    }
}

// ---------- strict spec length check ----------
static void require_len_matches_spec(char type, const std::vector<uint8_t>& msg) {
    const auto& specs = config().msg_specs;
    auto it = specs.find(type);
    if (it == specs.end()) {
        throw std::runtime_error(std::string("No spec loaded for msg type: ") + type);
    }
    uint32_t spec_len = it->second.total_length;
    if (spec_len != msg.size()) {
        throw std::runtime_error(
            std::string("Length mismatch for type '") + type +
            "': spec=" + std::to_string(spec_len) +
            " msg=" + std::to_string(msg.size())
        );
    }
}

// ---------- build ITCH payloads ----------
// S: 1 + 8 + 4 + 1 = 14
static std::vector<uint8_t> build_msg_S() {
    std::vector<uint8_t> m;
    m.reserve(14);
    m.push_back('S');
    push_be64(m, 1767085795602695293ULL);
    push_str_fixed(m, "XNET", 4);
    m.push_back('O'); // SystemEvent example
    require_len_matches_spec('S', m);
    return m;
}

// R: 59
static std::vector<uint8_t> build_msg_R() {
    std::vector<uint8_t> m;
    m.reserve(59);

    m.push_back('R');
    push_be64(m, 1767085795602695293ULL);
    push_str_fixed(m, "1309", 4);
    push_str_fixed(m, "JP3046510008", 12);
    push_str_fixed(m, "XNET", 4);
    push_be32(m, 100);
    m.push_back(4);
    m.push_back('T');
    push_be64(m, 542400000ULL);
    push_be64(m, 580368000ULL);
    push_be64(m, 504432000ULL);

    require_len_matches_spec('R', m);
    return m;
}

// H: 1 + 8 + 4 + 4 + 1 = 18
static std::vector<uint8_t> build_msg_H() {
    std::vector<uint8_t> m;
    m.reserve(18);

    m.push_back('H');
    push_be64(m, 1767085795602695293ULL);
    push_str_fixed(m, "1309", 4);
    push_str_fixed(m, "XNET", 4);
    m.push_back('T'); // TradingState

    require_len_matches_spec('H', m);
    return m;
}

// J: per your spec JSON you posted: total was showing 41 in your loader output.
// Fields you posted for J:
// 1 + 8 + 4 + 4 + 8(string) + 8 + 8 = 41
static std::vector<uint8_t> build_msg_J() {
    std::vector<uint8_t> m;
    m.reserve(41);

    m.push_back('J');
    push_be64(m, 1767085795602695293ULL);
    push_str_fixed(m, "1309", 4);
    push_str_fixed(m, "XNET", 4);

    // IMPORTANT: your J spec has ReferencePrice as type "string" size 8
    // so we push 8 bytes of ASCII digits (example). If you change spec to uint64,
    // change this to push_be64.
    push_str_fixed(m, "54240000", 8);

    push_be64(m, 580368000ULL);
    push_be64(m, 504432000ULL);

    require_len_matches_spec('J', m);
    return m;
}

// P: your loader output showed len=48 (means your P spec sums to 48).
// The field list you posted originally would sum to 48 if TradeDate is 4 bytes,
// SettleDate 1, TradeType 1, PriceType 1, plus others.
static std::vector<uint8_t> build_msg_P() {
    std::vector<uint8_t> m;
    m.reserve(48);

    m.push_back('P');
    push_be64(m, 1767100741497327578ULL);
    push_str_fixed(m, "1309", 4);
    push_str_fixed(m, "XNET", 4);

    // TradeDate uint32: example 20251230
    push_be32(m, 20251230U);

    // SettleDate uint8: example 2
    m.push_back(2);

    // TradeType char: 'S'
    m.push_back('S');

    // PriceType char: 'L'
    m.push_back('L');

    push_be64(m, 100ULL);        // ExecutedQuantity
    push_be64(m, 535000000ULL);  // ExecutionPrice
    push_be64(m, 202512300000001482ULL); // MatchNumber (example)

    require_len_matches_spec('P', m);
    return m;
}

// G: 1 + 8 = 9
static std::vector<uint8_t> build_msg_G() {
    std::vector<uint8_t> m;
    m.reserve(9);

    m.push_back('G');
    push_be64(m, 5694ULL);

    require_len_matches_spec('G', m);
    return m;
}

// ---------- wrap N messages into one MoldUDP64 packet ----------
static std::vector<uint8_t> build_mold_packet(
    const char session10[10],
    uint64_t start_seq,
    const std::vector<std::vector<uint8_t>>& msgs)
{
    std::vector<uint8_t> p;
    size_t total = 10 + 8 + 2;
    for (const auto& m : msgs) total += 2 + m.size();
    p.reserve(total);

    // session[10]
    for (int i = 0; i < 10; ++i) p.push_back(uint8_t(session10[i]));

    // sequence_number
    push_be64(p, start_seq);

    // message_count
    push_be16(p, (uint16_t)msgs.size());

    // blocks
    for (const auto& m : msgs) {
        push_be16(p, (uint16_t)m.size());
        p.insert(p.end(), m.begin(), m.end());
    }

    return p;
}

int main() {
    try {
        load_config("config/config.ini");

        // session just for display (10 bytes)
        const char sess[10] = {'1','7','6','7','0','8','5','7','9','5'};

        // Build one packet containing all message types
        std::vector<std::vector<uint8_t>> msgs;
        msgs.push_back(build_msg_S());
        msgs.push_back(build_msg_R());
        msgs.push_back(build_msg_H());
        msgs.push_back(build_msg_J());
        msgs.push_back(build_msg_P());
        msgs.push_back(build_msg_G());

        // seq=1, count=6
        auto pkt = build_mold_packet(sess, 1, msgs);

        DecodeOptions opt;
        opt.verbose = false;

        decode_moldudp64_packet(pkt.data(), pkt.size(), opt);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
}
