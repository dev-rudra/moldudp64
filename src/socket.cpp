#include "socket.h"

#include <cstring>
#include <iostream>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

UdpMcastReceiver::UdpMcastReceiver() : fd_(-1) {}
UdpMcastReceiver::~UdpMcastReceiver() { close(); }

void UdpMcastReceiver::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool UdpMcastReceiver::set_rcvbuf(int bytes) {
    if (fd_ < 0) return false;
    return ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) == 0;
}

bool UdpMcastReceiver::open(const std::string& mcast_ip,
                            uint16_t mcast_port,
                            const std::string& interface_ip,
                            const std::string& source_ip) {
    close();

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        perror("socket");
        return false;
    }

    int reuse = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(mcast_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close();
        return false;
    }

    // Join multicast: SSM if source_ip provided, else ASM
    if (!source_ip.empty()) {
        ip_mreq_source mreq{};
        mreq.imr_multiaddr.s_addr  = ::inet_addr(mcast_ip.c_str());
        mreq.imr_interface.s_addr  = ::inet_addr(interface_ip.c_str());
        mreq.imr_sourceaddr.s_addr = ::inet_addr(source_ip.c_str());

        if (::setsockopt(fd_, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("IP_ADD_SOURCE_MEMBERSHIP");
            close();
            return false;
        }
        std::cout << "INFO : Joined : " << mcast_ip << " Source: " << source_ip << "\n";
    } else {
        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = ::inet_addr(mcast_ip.c_str());
        mreq.imr_interface.s_addr = ::inet_addr(interface_ip.c_str());

        if (::setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("IP_ADD_MEMBERSHIP");
            close();
            return false;
        }
        std::cout << "INFO : Joined : " << mcast_ip << "\n";
    }

    return true;
}

int UdpMcastReceiver::recv(uint8_t* buf, int cap) {
    if (fd_ < 0) return -1;
    return (int)::recvfrom(fd_, buf, cap, 0, nullptr, nullptr);
}
