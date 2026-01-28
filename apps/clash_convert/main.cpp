#include "clash/clash_yaml_importer.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

using nlohmann::json;

static void save_json_file(const std::string& path, const json& j) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error("cannot write file: " + path);
    }
    ofs << j.dump(2);
}

int main(int argc, char** argv) {
    // Usage: clash_convert <clash.yaml> <out_config.json> [group_name]
    if (argc < 3) {
        std::cout << "Usage: clash_convert <clash.yaml> <out_config.json> [group_name]\n";
        return 2;
    }

    const std::string yaml_path = argv[1];
    const std::string out_path = argv[2];
    const std::string group_name = (argc >= 4) ? argv[3] : "WARP";

    try {
        const auto doc = proxycore::clash::ClashYamlImporter::load_from_file(yaml_path);

        // Найдём группу
        const proxycore::clash::ProxyGroup* grp = nullptr;
        for (const auto& g : doc.groups) {
            if (g.name == group_name) { grp = &g; break; }
        }
        if (!grp || grp->proxies.empty()) {
            throw std::runtime_error("group not found or empty: " + group_name);
        }

        // Выбираем первый прокси из группы (по имени из YAML)
        const std::string active_proxy_name = grp->proxies.front();

        // Собираем наш config.json
        json cfg;

        cfg["inbounds"]["socks5"] = {
            {"enabled", true},
            {"bind", "127.0.0.1"},
            {"port", 1080}
        };

        cfg["active_profile"] = "home";

        json profile;
        profile["id"] = "home";

        // nodes: direct + все WG прокси из YAML как "wireguard"
        json nodes = json::array();
        nodes.push_back({ {"id","direct"},{"type","direct"} });

        // Маппинг "оригинальное имя из YAML" -> "ascii id (warp_N)"
        std::unordered_map<std::string, std::string> name_to_id;
        int idx = 0;

        for (const auto& p : doc.proxies) {
            if (p.type != "wireguard") continue;

            ++idx;
            const std::string node_id = "warp_" + std::to_string(idx);

            name_to_id[p.name] = node_id;

            json node;
            node["id"] = node_id;
            node["display_name"] = p.name;
            node["type"] = "wireguard";

            node["wireguard"] = {
                {"server", p.wg.server},
                {"port", p.wg.port},
                {"ip", p.wg.ip},
                {"ipv6", p.wg.ipv6},
                {"private_key", p.wg.private_key},
                {"public_key", p.wg.public_key},
                {"mtu", p.wg.mtu},
                {"udp", p.wg.udp},
                {"remote_dns_resolve", p.wg.remote_dns_resolve},
                {"dns", p.wg.dns},
                {"allowed_ips", p.wg.allowed_ips},
                {"reserved", p.wg.reserved}
            };

            if (p.awg.has_value()) {
                json awg;
                awg["jc"] = p.awg->jc;
                awg["jmin"] = p.awg->jmin;
                awg["jmax"] = p.awg->jmax;
                awg["s1"] = p.awg->s1;
                awg["s2"] = p.awg->s2;
                awg["h1"] = p.awg->h1;
                awg["h2"] = p.awg->h2;
                awg["h3"] = p.awg->h3;
                awg["h4"] = p.awg->h4;
                awg["raw"] = p.awg->raw;
                node["amnezia_wg_option"] = awg;
            }

            nodes.push_back(node);
        }

        profile["nodes"] = nodes;

        // Определяем ascii-id выбранного прокси
        auto it = name_to_id.find(active_proxy_name);
        if (it == name_to_id.end()) {
            throw std::runtime_error("cannot map active proxy name to ascii id (encoding issue?)");
        }
        const std::string active_proxy_id = it->second;

        // rules: пока просто пример
        json rules = json::array();
        rules.push_back({ {"domain","youtube.com"},{"action","proxy"},{"node", active_proxy_id} });
        rules.push_back({ {"domain","googlevideo.com"},{"action","proxy"},{"node", active_proxy_id} });
        rules.push_back({ {"domain","ytimg.com"},{"action","proxy"},{"node", active_proxy_id} });
        rules.push_back({ {"domain","example.com"},{"action","direct"} });

        profile["rules"] = rules;

        cfg["profiles"] = json::array({ profile });
        cfg["meta"] = {
            {"source", "clash"},
            {"group", group_name},
            {"selected_proxy_name", active_proxy_name},
            {"selected_proxy_id", active_proxy_id}
        };

        save_json_file(out_path, cfg);

        std::cout << "OK\n";
        std::cout << "Selected from group '" << group_name << "': " << active_proxy_id << "\n";
        std::cout << "Wrote: " << out_path << "\n";
        return 0;
    }
    catch (const std::exception& ex) {
        std::cout << "error: " << ex.what() << "\n";
        return 1;
    }
}