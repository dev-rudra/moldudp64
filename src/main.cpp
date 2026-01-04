#include "config.h"
#include "decoder.h"
#include "socket.h"

#include <csignal>
#include <iostream>
#include <cstring>      // memset
#include <unistd.h>     // write()

#if defined(__linux__)
  #include <sys/socket.h> // mmsghdr
  #include <sys/uio.h>    // iovec
#endif

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

    // Packet-level output buffer (one write per UDP packet)
    // Increase if you ever expect very large packet message_count + verbose.
    alignas(64) static char outbuf[256 * 1024];

#if defined(__linux__)
    // --- Batch receive setup ---
    constexpr int BATCH = 32;    // tune: 16/32/64
    constexpr int MTU   = 65536; // safe upper bound for UDP payload

    // Note: alignas on this array may be ignored on some compilers; not critical.
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

    while (!g_stop) {
        int n = rx.recv_batch(msgs, BATCH);
        if (n <= 0) continue;

        for (int i = 0; i < n; ++i) {
            size_t bytes = (size_t)msgs[i].msg_len;
            if (bytes == 0) continue;

            size_t outn = decode_moldudp64_packet_to_buffer(
                bufs[i], bytes, opt, outbuf, sizeof(outbuf));

            if (outn) (void)!::write(1, outbuf, outn);
        }
    }
#else
    // Portable fallback (non-Linux): recvfrom one-by-one
    constexpr int MTU = 65536;
    alignas(64) static uint8_t buf[MTU];

    while (!g_stop) {
        int n = rx.recv(buf, MTU);
        if (n <= 0) continue;

        size_t outn = decode_moldudp64_packet_to_buffer(
            buf, (size_t)n, opt, outbuf, sizeof(outbuf));

        if (outn) (void)!::write(1, outbuf, outn);
    }
#endif

    std::cout << "INFO : stopped\n";
    return 0;
}

