#include "clash_yaml_importer.hpp"

#include <fstream>
#include <sstream>

namespace proxycore::clash {

    static std::string as_string(const YAML::Node& n, const char* key, const std::string& def = {}) {
        auto v = n[key];
        if (!v) return def;
        return v.as<std::string>();
    }

    static int as_int(const YAML::Node& n, const char* key, int def = 0) {
        auto v = n[key];
        if (!v) return def;
        return v.as<int>();
    }

    static bool as_bool(const YAML::Node& n, const char* key, bool def = false) {
        auto v = n[key];
        if (!v) return def;
        return v.as<bool>();
    }

    static std::uint16_t as_u16(const YAML::Node& n, const char* key, std::uint16_t def = 0) {
        auto v = n[key];
        if (!v) return def;
        int x = v.as<int>();
        if (x < 0) return def;
        if (x > 65535) return def;
        return static_cast<std::uint16_t>(x);
    }

    YAML::Node ClashYamlImporter::load_yaml(const std::string& path) {
        return YAML::LoadFile(path);
    }

    YAML::Node ClashYamlImporter::normalize_merges(const YAML::Node& node) {
        // Рекурсивно обрабатываем map/seq.
        if (!node) return node;

        if (node.IsSequence()) {
            YAML::Node out(YAML::NodeType::Sequence);
            for (const auto& it : node) {
                out.push_back(normalize_merges(it));
            }
            return out;
        }

        if (!node.IsMap()) {
            return node;
        }

        // Копируем map
        YAML::Node out(YAML::NodeType::Map);
        for (const auto& kv : node) {
            const auto key = kv.first.as<std::string>();
            if (key == "<<") continue; // обработаем отдельно
            out[kv.first] = normalize_merges(kv.second);
        }

        // Обрабатываем merge key (если есть)
        YAML::Node merge = node["<<"];
        if (merge) {
            auto merge_map_into = [&](const YAML::Node& m) {
                if (!m || !m.IsMap()) return;
                for (const auto& kv : m) {
                    const auto k = kv.first.as<std::string>();
                    if (!out[kv.first]) {
                        out[kv.first] = normalize_merges(kv.second);
                    }
                }
                };

            if (merge.IsMap()) {
                merge_map_into(merge);
            }
            else if (merge.IsSequence()) {
                for (const auto& m : merge) merge_map_into(m);
            }
        }

        return out;
    }

    WarpCommon ClashYamlImporter::parse_wg_common(const YAML::Node& p) {
        WarpCommon w;
        w.type = as_string(p, "type");
        w.private_key = as_string(p, "private-key");
        w.server = as_string(p, "server");
        w.port = as_u16(p, "port");
        w.ip = as_string(p, "ip");
        w.ipv6 = as_string(p, "ipv6");
        w.public_key = as_string(p, "public-key");
        w.udp = as_bool(p, "udp", true);
        w.mtu = as_int(p, "mtu", 0);
        w.remote_dns_resolve = as_bool(p, "remote-dns-resolve", false);

        if (auto a = p["allowed-ips"]; a && a.IsSequence()) {
            for (const auto& it : a) w.allowed_ips.push_back(it.as<std::string>());
        }

        if (auto r = p["reserved"]; r && r.IsSequence()) {
            for (const auto& it : r) w.reserved.push_back(it.as<int>());
        }

        if (auto d = p["dns"]; d && d.IsSequence()) {
            for (const auto& it : d) w.dns.push_back(it.as<std::string>());
        }

        return w;
    }

    std::optional<AmneziaWgOption> ClashYamlImporter::parse_awg(const YAML::Node& p) {
        auto a = p["amnezia-wg-option"];
        if (!a || !a.IsMap()) return std::nullopt;

        AmneziaWgOption o;
        o.jc = as_int(a, "jc", 0);
        o.jmin = as_int(a, "jmin", 0);
        o.jmax = as_int(a, "jmax", 0);
        o.s1 = as_int(a, "s1", 0);
        o.s2 = as_int(a, "s2", 0);
        o.h1 = as_int(a, "h1", 0);
        o.h2 = as_int(a, "h2", 0);
        o.h3 = as_int(a, "h3", 0);
        o.h4 = as_int(a, "h4", 0);

        // сохраним всё остальное как raw, чтобы не потерять i1/i2/j1/itime и т.п.
        for (const auto& kv : a) {
            const auto k = kv.first.as<std::string>();
            if (k == "jc" || k == "jmin" || k == "jmax" || k == "s1" || k == "s2" ||
                k == "h1" || k == "h2" || k == "h3" || k == "h4") {
                continue;
            }
            if (kv.second.IsScalar()) {
                o.raw[k] = kv.second.as<std::string>();
            }
            else {
                // не скаляр — сериализуем в строку как есть
                o.raw[k] = YAML::Dump(kv.second);
            }
        }

        return o;
    }

    Proxy ClashYamlImporter::parse_proxy(const YAML::Node& p0) {
        // Сначала применяем YAML merge
        YAML::Node p = normalize_merges(p0);

        Proxy pr;
        pr.name = as_string(p, "name");
        pr.type = as_string(p, "type");

        pr.wg = parse_wg_common(p);
        pr.awg = parse_awg(p);
        return pr;
    }

    ProxyGroup ClashYamlImporter::parse_group(const YAML::Node& g) {
        ProxyGroup out;
        out.name = as_string(g, "name");
        out.type = as_string(g, "type");

        if (auto p = g["proxies"]; p && p.IsSequence()) {
            for (const auto& it : p) out.proxies.push_back(it.as<std::string>());
        }
        return out;
    }

    ClashDoc ClashYamlImporter::load_from_file(const std::string& path) {
        YAML::Node root = load_yaml(path);

        ClashDoc doc;

        if (auto ps = root["proxies"]; ps && ps.IsSequence()) {
            for (const auto& p : ps) {
                doc.proxies.push_back(parse_proxy(p));
            }
        }

        if (auto gs = root["proxy-groups"]; gs && gs.IsSequence()) {
            for (const auto& g : gs) {
                doc.groups.push_back(parse_group(g));
            }
        }

        return doc;
    }

} // namespace proxycore::clash