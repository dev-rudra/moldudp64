#pragma once

#include <string>
#include <cstdint>

class UdpMcastReceiver {
public:
    UdpMcastReceiver();
    ~UdpMcastReceiver();

    // Join multicast group on interface, optional SSM source IP
    bool open(const std::string& mcast_ip,
              uint16_t mcast_port,
              const std::string& interface_ip,
              const std::string& source_ip); // "" => ASM, else SSM

    // Receive one datagram
    // returns bytes received, 0/neg on error
    int recv(uint8_t* buf, int cap);

    // Optional: increase OS receive buffer
    bool set_rcvbuf(int bytes);

    void close();

private:
    int fd_;
};
