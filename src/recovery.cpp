#include "recovery.h"
#include "decoder.h"
#include "config.h"
#include <cstring>
#include <cerrno>
#include <endian.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>

#pragma pack(push, 1)
struct RereqPkt {
    char     session[10];
    uint64_t seq_be;
    uint16_t count_be;
};
#pragma pack(pop)

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

Rerequester::Rerequester() : fd_(-1), ip_be_(0), port_be_(0) {}
Rerequester::~Rerequester() { close(); }

bool Rerequester::open(const char* ip, uint16_t port, int rcvbuf_bytes, int timeout_ms) {
    close();

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) return false;

    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_bytes, sizeof(rcvbuf_bytes));

    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ip_be_ = ::inet_addr(ip);
    port_be_ = htons(port);

    return (ip_be_ != INADDR_NONE && port != 0);
}

void Rerequester::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

uint64_t Rerequester::recover(const char session10[10],
                              uint64_t start_seq,
                              uint64_t count,
                              const DecodeOptions& opt) {
    if (fd_ < 0 || count == 0) return 0;

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip_be_;
    dst.sin_port = port_be_;

    // Output buffer: one write per recovered packet
    alignas(64) static char outbuf[256 * 1024];
    alignas(64) static uint8_t rxbuf[65536];

    uint64_t recovered = 0;
    uint64_t cur_seq = start_seq;
    uint64_t remaining = count;

    const uint16_t MAX_PER_REQ = config().recovery.max_recovery_message_count; 

    while (remaining > 0) {
        uint16_t req = (remaining > MAX_PER_REQ) ? MAX_PER_REQ : (uint16_t)remaining;

        RereqPkt pkt{};
        std::memset(pkt.session, ' ', sizeof(pkt.session));
        std::memcpy(pkt.session, session10, 10);
        pkt.seq_be   = htobe64(cur_seq);
        pkt.count_be = htobe16(req);

        if (::sendto(fd_, &pkt, sizeof(pkt), 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
            std::cerr << "RECOVERY sendto failed errno=" << errno << "\n";
            break;
        }

        std::cerr << "RECOVERY request start=" << cur_seq << " count=" << req << "\n";

        uint64_t got = 0;
        int timeouts = 0;

        while (got < req) {
            int n = (int)::recvfrom(fd_, rxbuf, sizeof(rxbuf), 0, nullptr, nullptr);
            if (n <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (++timeouts >= 3) break; // QA: 3 timeouts then stop this request
                    continue;
                }
                std::cerr << "RECOVERY recvfrom failed errno=" << errno << "\n";
                break;
            }

            // decode recovered packet and print
            size_t outn = decode_moldudp64_packet_to_buffer(rxbuf, (size_t)n, opt, outbuf, sizeof(outbuf));
            if (outn) (void)!::write(1, outbuf, outn);

            // count recovered messages (from Mold header)
            if ((size_t)n >= sizeof(MoldHeaderRaw)) {
                auto* h = reinterpret_cast<const MoldHeaderRaw*>(rxbuf);
                uint16_t mc = be16(reinterpret_cast<const uint8_t*>(&h->message_count_be));
                got += mc;
            }
        }

        if (got == 0) {
            std::cerr << "RECOVERY stalled start=" << cur_seq << " req=" << req << "\n";
            break;
        }

        recovered += got;
        cur_seq += got;
        remaining = (remaining > got) ? (remaining - got) : 0;
    }

    std::cerr << "RECOVERY done recovered=" << recovered << "\n";
    return recovered;
}
