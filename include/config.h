#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

struct NetConfig {
    std::string mcast_ip;
    uint16_t    mcast_port;
    std::string mcast_source_ip;
    std::string interface_ip;
    std::string rerequest_ip;
    uint16_t    rerequest_port;
};

enum class FieldType : uint8_t {
    CHAR,
    UINT8,
    UINT32,
    UINT64,
    STRING
};

struct FieldSpec {
    std::string name;
    FieldType   type;
    uint8_t     size;
    uint32_t    offset;
};

struct MsgSpec {
    char                   msg_type;
    uint32_t               total_length;
    std::vector<FieldSpec> fields;
};

struct AppConfig {
    NetConfig net;
    std::unordered_map<char, MsgSpec> msg_specs;
};

void load_config(const char* ini_path);
const AppConfig& config();
