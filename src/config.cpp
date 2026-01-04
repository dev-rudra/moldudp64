#include "config.h"

#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

static AppConfig g_cfg;

static std::string trim(std::string s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

static FieldType parse_field_type(const std::string& t) {
    if (t == "char")   return FieldType::CHAR;
    if (t == "uint8")  return FieldType::UINT8;
    if (t == "uint32") return FieldType::UINT32;
    if (t == "uint64") return FieldType::UINT64;
    if (t == "string") return FieldType::STRING;
    throw std::runtime_error("Unknown field type: " + t);
}

static void load_spec(const fs::path& spec_file, AppConfig& cfg) {
    std::ifstream f(spec_file);
    if (!f) throw std::runtime_error("Cannot open spec json: " + spec_file.string());

    json root;
    f >> root;

    cfg.msg_specs.clear();

    for (auto& [k, msg] : root.items()) {
        if (k.empty()) continue;
        if (!msg.is_object()) throw std::runtime_error("Spec message must be object: " + k);

        MsgSpec ms{};
        ms.msg_type = k[0];

        const auto& fields = msg.at("fields");
        if (!fields.is_array()) throw std::runtime_error("'fields' must be array for: " + k);

        uint32_t offset = 0;
        ms.fields.reserve(fields.size());

        for (const auto& field : fields) {
            FieldSpec fspec{};
            fspec.name   = field.at("name").get<std::string>();
            fspec.type   = parse_field_type(field.at("type").get<std::string>());
            fspec.size   = field.at("size").get<uint8_t>();
            fspec.offset = offset;

            offset += fspec.size;
            ms.fields.push_back(std::move(fspec));
        }

        ms.total_length = offset;
        cfg.msg_specs[ms.msg_type] = std::move(ms);
    }
}

void load_config(const char* ini_path) {
    std::ifstream f(ini_path);
    if (!f) throw std::runtime_error(std::string("Cannot open ini file: ") + ini_path);

    std::string spec_rel;
    std::string line;

    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;

        auto pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));

        if      (key == "mcast_ip")               g_cfg.net.mcast_ip = val;
        else if (key == "mcast_port")             g_cfg.net.mcast_port = (uint16_t)std::stoi(val);
        else if (key == "mcast_source_ip")        g_cfg.net.mcast_source_ip = val;
        else if (key == "interface_ip")           g_cfg.net.interface_ip = val;
        else if (key == "mcast_rerequester_ip")   g_cfg.net.rerequest_ip = val;
        else if (key == "mcast_rerequester_port") g_cfg.net.rerequest_port = (uint16_t)std::stoi(val);
        else if (key == "protocol_spec")          spec_rel = val;
    }

    if (spec_rel.empty()) throw std::runtime_error("protocol_spec not found in ini");

    fs::path ini_dir  = fs::path(ini_path).parent_path();
    fs::path spec_file = ini_dir / spec_rel;

    load_spec(spec_file, g_cfg);
}

const AppConfig& config() {
    return g_cfg;
}
