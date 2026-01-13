#include "config.h"
#include "decoder.h"
#include "socket.h"

#include <csignal>
#include <iostream>
#include <cstring>
#include <unistd.h>

#include <sys/socket.h> // mmsghdr
#include <sys/uio.h>    // iovec

static volatile std::sig_atomic_t g_stop = 0;
static void on_sigint(int) { g_stop = 1; }

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
static inline uint64_t be64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48) | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32) |
           (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16) | (uint64_t(p[6]) << 8)  | uint64_t(p[7]);
}

static bool read_mold_header(const uint8_t* buf, size_t len,
                            char session10[10], uint64_t& seq, uint16_t& cnt) {
    if (!buf || len < sizeof(MoldHeaderRaw)) return false;
    const auto* h = reinterpret_cast<const MoldHeaderRaw*>(buf);
    std::memcpy(session10, h->session, 10);
    seq = be64(reinterpret_cast<const uint8_t*>(&h->sequence_number_be));
    cnt = be16(reinterpret_cast<const uint8_t*>(&h->message_count_be));
    return true;
}

int main() {
    std::signal(SIGINT, on_sigint);

    try {
        load_config("config/config.ini");
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }

    const auto& cfg = config();

    UdpMcastReceiver rx;
    if (!rx.open(cfg.net.mcast_ip,
                 cfg.net.mcast_port,
                 cfg.net.interface_ip,
                 cfg.net.mcast_source_ip)) {
        std::cerr << "FATAL: multicast open failed\n";
        return 1;
    }

    rx.set_rcvbuf(4 * 1024 * 1024);

    DecodeOptions opt;
    opt.verbose = false;

    // one write per UDP packet
    alignas(64) static char outbuf[256 * 1024];

    // --- batch receive ---
    constexpr int BATCH = 32;   // tune: 16/32/64
    constexpr int MTU   = 65536;

    alignas(64) static uint8_t bufs[BATCH][MTU];
    static struct iovec iov[BATCH];
    static struct mmsghdr msgs[BATCH];

    for (int i = 0; i < BATCH; ++i) {
        std::memset(&msgs[i], 0, sizeof(msgs[i]));
        std::memset(&iov[i], 0, sizeof(iov[i]));
        iov[i].iov_base = bufs[i];
        iov[i].iov_len  = MTU;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    uint64_t expected_seq = 0;

    while (!g_stop) {
        int n = rx.recv_batch(msgs, BATCH);
        if (n <= 0) continue;

        for (int i = 0; i < n; ++i) {
            size_t bytes = (size_t)msgs[i].msg_len;
            if (bytes == 0) continue;

            char session10[10];
            uint64_t seq;
            uint16_t cnt;

            if (!read_mold_header(bufs[i], bytes, session10, seq, cnt)) continue;

            if (expected_seq == 0) expected_seq = seq;

            // GAP DETECT
            if (seq > expected_seq) {
                uint64_t gap = seq - expected_seq;
                std::cerr << "WARN: GAP expected=" << expected_seq
                          << " got=" << seq
                          << " missing=" << gap
                          << " session=" << std::string(session10, 10)
                          << "\n";

                // QA-level behavior for now: resync to live
                expected_seq = seq;
            } else if (seq < expected_seq) {
                // stale/duplicate packet
                continue;
            }

            // decode + write
            size_t outn = decode_moldudp64_packet_to_buffer(bufs[i], bytes, opt, outbuf, sizeof(outbuf));
            if (outn) (void)!::write(1, outbuf, outn);

            // advance expected
            if (cnt != 0xFFFF) expected_seq += cnt;
        }
    }

    std::cout << "INFO : stopped\n";
    return 0;
}
