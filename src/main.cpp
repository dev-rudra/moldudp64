#include "config.h"
#include "decoder.h"
#include "socket.h"
#include "recovery.h"

#include <csignal>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <getopt.h>

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

static void usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [-g] [-s <seq>] [-n <count>] [-v]\n\n"
        << "Options:\n"
        << "  -g            Enable gap-fill (rerequest missing sequences)\n"
        << "  -s <seq>      Start expected sequence at <seq> (implies gap-fill is useful)\n"
        << "  -n <count>    Stop after decoding <count> messages (QA testing)\n"
        << "  -v            Verbose decode (field names etc. if decoder supports)\n";
}

int main(int argc, char** argv) {
    std::signal(SIGINT, on_sigint);

    bool enable_gap_fill = false;   // <-- default OFF (safe)
    bool verbose = false;
    uint64_t start_seq = 0;
    uint64_t max_msgs = 0;

    int opt;
    while ((opt = ::getopt(argc, argv, "hgs:n:v")) != -1) {
        switch (opt) {
            case 'h': usage(argv[0]); return 0;
            case 'g': enable_gap_fill = true; break;
            case 's':
                start_seq = std::stoull(optarg);
                // do NOT force enable_gap_fill automatically; user must pass -g
                break;
            case 'n': max_msgs = std::stoull(optarg); break;
            case 'v': verbose = true; break;
            default: usage(argv[0]); return 1;
        }
    }

    try {
        load_config("config/config.ini");
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }

    const auto& cfg = config();

    // Multicast RX
    UdpMcastReceiver rx;
    if (!rx.open(cfg.net.mcast_ip,
                 cfg.net.mcast_port,
                 cfg.net.interface_ip,
                 cfg.net.mcast_source_ip)) {
        std::cerr << "FATAL: multicast open failed\n";
        return 1;
    }
    rx.set_rcvbuf(4 * 1024 * 1024);

    // Decoder options
    DecodeOptions opt_dec;
    opt_dec.verbose = verbose;

    // Rerequester (only used if -g passed)
    Rerequester rr;
    bool rr_ok = false;
    if (enable_gap_fill) {
        rr_ok = rr.open(cfg.net.rerequest_ip.c_str(), cfg.net.rerequest_port);
        if (!rr_ok) {
            std::cerr << "WARN: gap-fill requested but rerequester open failed; disabling gap-fill\n";
            enable_gap_fill = false;
        }
    }

    // One write per UDP packet (decoder writes into this buffer)
    alignas(64) static char outbuf[256 * 1024];

    // Batch receive
    constexpr int BATCH = 32;
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

    uint64_t expected_seq = start_seq;  // 0 means "sync to first packet"
    uint64_t total_msgs = 0;

    while (!g_stop) {
        if (max_msgs > 0 && total_msgs >= max_msgs) break;

        int n = rx.recv_batch(msgs, BATCH);
        if (n <= 0) continue;

        for (int i = 0; i < n; ++i) {
            if (max_msgs > 0 && total_msgs >= max_msgs) break;

            size_t bytes = (size_t)msgs[i].msg_len;
            if (bytes == 0) continue;

            char session10[10];
            uint64_t seq;
            uint16_t cnt;

            if (!read_mold_header(bufs[i], bytes, session10, seq, cnt)) continue;

            // Sync expected seq to first packet (live mode)
            if (expected_seq == 0) expected_seq = seq;

            // End session marker (optional)
            if (cnt == 0xFFFF) {
                std::cerr << "INFO: END session=" << std::string(session10, 10)
                          << " seq=" << seq << "\n";
                continue;
            }

            // GAP detection
            if (seq > expected_seq) {
                uint64_t gap = seq - expected_seq;

                std::cerr << "GAP session=" << std::string(session10, 10)
                          << " range=" << expected_seq << "-" << (seq - 1)
                          << " count=" << gap << "\n";

                if (enable_gap_fill && rr_ok) {
                    uint64_t rec = rr.recover(session10, expected_seq, gap, opt_dec);
                    expected_seq += rec;

                    if (rec < gap) {
                        std::cerr << "WARN: RECOVERY partial recovered=" << rec
                                  << " still_missing=" << (gap - rec) << "\n";
                    }
                }

                // Sync to live packet after recovery attempt
                expected_seq = seq;
            } else if (seq < expected_seq) {
                // stale/duplicate
                continue;
            }

            // Decode live packet (one write per packet)
            size_t outn = decode_moldudp64_packet_to_buffer(bufs[i], bytes, opt_dec, outbuf, sizeof(outbuf));
            if (outn) (void)!::write(1, outbuf, outn);

            // Count & advance state
            total_msgs += cnt;
            expected_seq += cnt;
        }
    }

    std::cerr << "INFO: stopped msgs=" << total_msgs << " expected_seq=" << expected_seq << "\n";
    return 0;
}
