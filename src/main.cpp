#include "config.h"
#include "decoder.h"
#include "socket.h"

#include <csignal>
#include <iostream>
#include <cstring>      // memset
#include <sys/socket.h> // mmsghdr
#include <sys/uio.h>    // iovec

static volatile std::sig_atomic_t g_stop = 0;

static void on_sigint(int) {
    g_stop = 1;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

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

    // --- Batch receive setup ---
    constexpr int BATCH = 32;         // tune: 16/32/64
    constexpr int MTU   = 65536;      // safe upper bound for UDP payload

    static alignas(64) uint8_t bufs[BATCH][MTU];
    static struct iovec iov[BATCH];
    static struct mmsghdr msgs[BATCH];

    for (int i = 0; i < BATCH; ++i) {
        std::memset(&msgs[i], 0, sizeof(msgs[i]));
        iov[i].iov_base = bufs[i];
        iov[i].iov_len  = MTU;

        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while (!g_stop) {
        int n = rx.recv_batch(msgs, BATCH);
        if (n <= 0) continue;

        for (int i = 0; i < n; ++i) {
            const uint8_t* p = bufs[i];
            size_t bytes = (size_t)msgs[i].msg_len;

            if (bytes == 0) continue;
            decode_moldudp64_packet(p, bytes, opt);
        }
    }

    std::cout << "INFO : stopped\n";
    return 0;
}

