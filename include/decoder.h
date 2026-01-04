#pragma once

#include <cstddef>
#include <cstdint>

struct DecodeOptions {
    bool verbose = false;
    bool print_hex_strings = false;
};

// Decode one MoldUDP64 packet into caller-provided buffer.
// Returns number of bytes written to `out`.
size_t decode_moldudp64_packet_to_buffer(const uint8_t* buf, size_t len,
                                        const DecodeOptions& opt,
                                        char* out, size_t out_cap);
