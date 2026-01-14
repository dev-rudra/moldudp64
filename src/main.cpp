#include "config.h"
#include "decoder.h"
#include "socket.h"
#include "recovery.h"
#include <csignal>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <cstdio>

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
        << "  -g            Live mode with recovery (rerequest on gaps)\n"
        << "  -s <seq>      Download starting at <seq> using rerequest (session discovered from first live packet)\n"
        << "  -n <count>    Stop after decoding <count> messages (QA testing)\n"
        << "  -v            Verbose decode (field names etc. if decoder supports)\n";
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    std::signal(SIGINT, on_sigint);

    bool enable_gap_fill = false;
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

    const bool start_mode = (start_seq != 0);

    const bool auto_start_recover_enabled = true;

    const bool need_rereq = (enable_gap_fill || start_mode || auto_start_recover_enabled);

    // Rerequester (used for -g, -s, and optional auto-start recovery)
    Rerequester rr;
    bool rr_ok = false;
    if (need_rereq) {
        rr_ok = rr.open(cfg.net.rerequest_ip.c_str(), cfg.net.rerequest_port);
        if (!rr_ok) {
            if (start_mode) {
                std::cerr << "FATAL: -s requires rerequest, but rerequester open failed\n";
                return 1;
            }
            if (enable_gap_fill) {
                std::cerr << "WARN: -g requested but rerequester open failed; disabling recovery\n";
                enable_gap_fill = false;
            }
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

    bool initial_done = !start_mode;
    bool did_auto_start_recover = false;

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

            // End of Session 
            // >> {'1234567891', 4345, 65535}
            if (cnt == 0xFFFF) {
                char line[128];
                int  l = std::snprintf(line, sizeof(line),
                                       ">> {'%.*s', %llu, %u}\n",
                                       10, session10,
                                       (unsigned long long)seq,
                                       (unsigned)cnt);
                if (l > 0) (void)!::write(1, line, (size_t)l);
                continue;
            }

            // If -s was provided, the first live packet is used to discover session + "current".
            if (start_mode && !initial_done) {
                if (expected_seq == 0) expected_seq = 1; // safety; user likely passed -s anyway

                // Initial download via rerequest: [expected_seq .. seq-1]
                if (rr_ok && seq > expected_seq) {
                    uint64_t gap = seq - expected_seq;

                    uint64_t remaining = (max_msgs > 0 && total_msgs < max_msgs) ? (max_msgs - total_msgs) : 0;
                    uint64_t need = gap;
                    if (max_msgs > 0) {
                        if (remaining == 0) {
                            g_stop = 1;
                            break;
                        }
                        if (need > remaining) need = remaining;
                    }

                    if (need > 0) {
                        std::cerr << "DOWNLOAD session=" << std::string(session10, 10)
                                  << " from=" << expected_seq << " count=" << need << "\n";

                        uint64_t rec = rr.recover(session10, expected_seq, need, opt_dec);
                        total_msgs += rec;
                        expected_seq += rec;
                    }
                }

                // If -n was satisfied by download, stop.
                if (max_msgs > 0 && total_msgs >= max_msgs) {
                    g_stop = 1;
                    break;
                }

                // Sync to this live packet (best-effort) and decode it.
                expected_seq = seq;

                size_t outn = decode_moldudp64_packet_to_buffer(bufs[i], bytes, opt_dec, outbuf, sizeof(outbuf));
                if (outn) (void)!::write(1, outbuf, outn);

                total_msgs += cnt;
                expected_seq += cnt;
                initial_done = true;

                // -s without -g: "download then exit"
                if (!enable_gap_fill) {
                    if (max_msgs == 0 || total_msgs >= max_msgs) {
                        g_stop = 1;
                        break;
                    }
                }

                continue;
            }

            // one-time auto-start recovery in pure live mode.
            // If we miss the initial burst and our first packet is seq>1, recover [1..seq-1] once.
            if (!start_mode && auto_start_recover_enabled && !did_auto_start_recover) {
                if (expected_seq == 0 && rr_ok && seq > 1) {
                    uint64_t remaining = (max_msgs > 0 && total_msgs < max_msgs) ? (max_msgs - total_msgs) : 0;
                    uint64_t need = seq - 1;
                    if (max_msgs > 0) {
                        if (remaining == 0) { g_stop = 1; break; }
                        if (need > remaining) need = remaining;
                    }

                    if (need > 0) {
                        std::cerr << "AUTO-START-RECOVERY session=" << std::string(session10, 10)
                                  << " from=1 count=" << need << "\n";
                        uint64_t rec = rr.recover(session10, 1, need, opt_dec);
                        total_msgs += rec;
                    }
                }
                did_auto_start_recover = true;
            }

            // Live mode: sync expected seq to first packet
            if (expected_seq == 0) expected_seq = seq;

            // GAP detection
            if (seq > expected_seq) {
                uint64_t gap = seq - expected_seq;

                std::cerr << "GAP session=" << std::string(session10, 10)
                          << " range=" << expected_seq << "-" << (seq - 1)
                          << " count=" << gap << "\n";

                if (enable_gap_fill && rr_ok) {
                    uint64_t remaining = (max_msgs > 0 && total_msgs < max_msgs) ? (max_msgs - total_msgs) : 0;
                    uint64_t need = gap;
                    if (max_msgs > 0) {
                        if (remaining == 0) {
                            g_stop = 1;
                            break;
                        }
                        if (need > remaining) need = remaining;
                    }

                    uint64_t rec = rr.recover(session10, expected_seq, need, opt_dec);
                    total_msgs += rec;
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

            if (max_msgs > 0 && total_msgs >= max_msgs) {
                g_stop = 1;
                break;
            }
        }
    }

    std::cerr << "INFO: stopped msgs=" << total_msgs << " expected_seq=" << expected_seq << "\n";
    return 0;
}

