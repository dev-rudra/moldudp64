#pragma once
#include <cstdint>

struct DecodeOptions;

class Rerequester {
public:
    Rerequester();
    ~Rerequester();

    bool open(const char* ip, uint16_t port, int rcvbuf_bytes = 16 * 1024 * 1024, int timeout_ms = 500);
    void close();

    // Recover missing [start_seq .. start_seq+count-1]
    // Returns messages recovered (best-effort).
    uint64_t recover(const char session10[10],
                     uint64_t start_seq,
                     uint64_t count,
                     const DecodeOptions& opt);

private:
    int fd_;
    uint32_t ip_be_;
    uint16_t port_be_;
};
