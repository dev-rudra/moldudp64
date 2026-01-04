#include "config.h"
#include <iostream>

int main() {
    load_config("config/config.ini");

    const auto& cfg = config();

    std::cout << "Multicast IP: " << cfg.net.mcast_ip << "\n";
    std::cout << "Messages loaded: " << cfg.msg_specs.size() << "\n";

    for (const auto& [k, v] : cfg.msg_specs) {
        std::cout << "Msg " << k
                  << " len=" << v.total_length
                  << " fields=" << v.fields.size() << "\n";
    }
}
