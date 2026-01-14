#include "config.h"
#include <fstream>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <sys/stat.h>
#include <unistd.h> 
#include <cctype>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static AppConfig g_cfg;

static std::string trim(std::string s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

static bool file_exists_regular(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISREG(st.st_mode);
}

static std::string dirname_of(const std::string& path) {
    const std::string::size_type pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

static std::string join_path(const std::string& dir, const std::string& rel) {
    if (rel.empty()) return dir;
    if (!rel.empty() && (rel[0] == '/' || rel[0] == '\\')) return rel;
    if (dir.empty() || dir == ".") return rel;
    if (dir.back() == '/' || dir.back() == '\\') return dir + rel;
    return dir + "/" + rel;
}

static std::string to_lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

static FieldType parse_field_type(const std::string& t) {
    if (t == "char")   return FieldType::CHAR;

    if (t == "uint8")  return FieldType::UINT8;
    if (t == "uint16") return FieldType::UINT16;
    if (t == "uint32") return FieldType::UINT32;
    if (t == "uint64") return FieldType::UINT64;

    if (t == "int16")  return FieldType::INT16;
    if (t == "int32")  return FieldType::INT32;
    if (t == "int64")  return FieldType::INT64;

    if (t == "string") return FieldType::STRING;
    if (t == "binary") return FieldType::BINARY;

    throw std::runtime_error("Unknown field type: " + t);
}

static int expected_size(FieldType ft) {
    switch (ft) {
        case FieldType::CHAR:   return 1;
        case FieldType::UINT8:  return 1;
        case FieldType::UINT16: return 2;
        case FieldType::UINT32: return 4;
        case FieldType::UINT64: return 8;
        case FieldType::INT16:  return 2;
        case FieldType::INT32:  return 4;
        case FieldType::INT64:  return 8;
        case FieldType::STRING: return 0;
        case FieldType::BINARY: return 0;
        default: return -1;
    }
}

static void validate_field(const FieldSpec& f) {
    if (f.name.empty()) {
        throw std::runtime_error("Spec field name is empty");
    }
    if (f.size == 0) {
        throw std::runtime_error("Spec field '" + f.name + "' has size=0");
    }
    const int es = expected_size(f.type);
    if (es > 0 && f.size != (uint8_t)es) {
        throw std::runtime_error(
            "Spec field '" + f.name + "' has invalid size=" + std::to_string((int)f.size) +
            " for type (expected " + std::to_string(es) + ")"
        );
    }
}

static void load_spec(const std::string& spec_file, AppConfig& cfg) {
    if (!file_exists_regular(spec_file)) {
        throw std::runtime_error("Spec json does not exist or not a file: " + spec_file);
    }

    std::ifstream f(spec_file.c_str());
    if (!f) throw std::runtime_error("Cannot open spec json: " + spec_file);

    json root;
    f >> root;

    if (!root.is_object()) {
        throw std::runtime_error("Spec root must be object: " + spec_file);
    }

    cfg.msg_specs.clear();

    for (auto& it : root.items()) {
        const std::string& k = it.key();
        const json& msg = it.value();

        if (k.empty()) continue;
        if (!msg.is_object()) throw std::runtime_error("Spec message must be object: " + k);

        MsgSpec ms{};
        ms.msg_type = k[0];

        if (!msg.contains("fields")) {
            throw std::runtime_error("Spec message missing 'fields': " + k);
        }
        const auto& fields = msg.at("fields");
        if (!fields.is_array()) throw std::runtime_error("'fields' must be array for: " + k);

        uint32_t offset = 0;
        ms.fields.clear();
        ms.fields.reserve(fields.size());

        for (const auto& field : fields) {
            if (!field.is_object()) {
                throw std::runtime_error("Field entry must be object in msg: " + k);
            }
            FieldSpec fspec{};
            fspec.name   = field.at("name").get<std::string>();
            fspec.type   = parse_field_type(field.at("type").get<std::string>());
            fspec.size   = field.at("size").get<uint8_t>();
            fspec.offset = offset;

            validate_field(fspec);

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

    // for flat ini without section
    std::string section;

    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;

        if (line.front() == '[' && line.back() == ']') {
            section = to_lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }

        auto pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));

        // FEED_CHANNELS SECTION
        if (section.empty() || section == "feed_channels") {
            if      (key == "mcast_ip")               g_cfg.net.mcast_ip = val;
            else if (key == "mcast_port")             g_cfg.net.mcast_port = (uint16_t)std::stoi(val);
            else if (key == "mcast_source_ip")        g_cfg.net.mcast_source_ip = val;
            else if (key == "interface_ip")           g_cfg.net.interface_ip = val;
            else if (key == "mcast_rerequester_ip")   g_cfg.net.rerequest_ip = val;
            else if (key == "mcast_rerequester_port") g_cfg.net.rerequest_port = (uint16_t)std::stoi(val);
            else if (key == "protocol_spec")          spec_rel = val;
        }

        // RECOVERY_SETTINGS SECTION
        if (section == "recovery_settings") {
            if (key == "max_recovery_message_count") {
                g_cfg.recovery.max_recovery_message_count = (uint16_t)std::stoi(val);
            }
        }
    }

    if (spec_rel.empty()) throw std::runtime_error("protocol_spec not found in ini");

    const std::string ini_dir   = dirname_of(std::string(ini_path));
    const std::string spec_file = join_path(ini_dir, spec_rel);

    load_spec(spec_file, g_cfg);
}

const AppConfig& config() {
    return g_cfg;
}
