#include "config.h"
#include "decoder.h"
#include "socket.h"

#include <csignal>
#include <iostream>

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

    // Good default for market data bursts
    rx.set_rcvbuf(4 * 1024 * 1024);

    DecodeOptions opt;
    opt.verbose = false;

    // UDP max payload fits well in 64KB
    alignas(64) uint8_t buf[65536];

    while (!g_stop) {
        int n = rx.recv(buf, (int)sizeof(buf));
        if (n <= 0) continue;

        decode_moldudp64_packet(buf, (size_t)n, opt);
    }

    std::cout << "INFO : stopped\n";
    return 0;
}
