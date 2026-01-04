#pragma once

#include <cstddef>
#include <cstdint>

struct DecodeOptions {
    bool verbose = false;
    bool print_hex_strings = false;
};

void decode_moldudp64_packet(const uint8_t* buf, size_t len, const DecodeOptions& opt);
