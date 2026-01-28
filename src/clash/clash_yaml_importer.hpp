#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace proxycore::clash {

    struct WarpCommon {
        std::string type;               // "wireguard"
        std::string private_key;
        std::string server;
        std::uint16_t port = 0;
        std::string ip;
        std::string ipv6;
        std::string public_key;
        std::vector<std::string> allowed_ips;
        std::vector<int> reserved;
        bool udp = true;
        int mtu = 0;
        bool remote_dns_resolve = false;
        std::vector<std::string> dns;
    };

    struct AmneziaWgOption {
        int jc = 0;
        int jmin = 0;
        int jmax = 0;
        int s1 = 0;
        int s2 = 0;
        int h1 = 0;
        int h2 = 0;
        int h3 = 0;
        int h4 = 0;

        // В YAML встречаются i1/i2/j1/itime и т.п. — оставим как строки (raw), чтобы не потерять
        std::unordered_map<std::string, std::string> raw;
    };

    struct Proxy {
        std::string name;

        // тип узла
        std::string type; // ожидаем "wireguard"

        // wireguard/warp
        WarpCommon wg;
        std::optional<AmneziaWgOption> awg;
    };

    struct ProxyGroup {
        std::string name;
        std::string type; // select/fallback/url-test/etc
        std::vector<std::string> proxies;
    };

    struct ClashDoc {
        std::vector<Proxy> proxies;
        std::vector<ProxyGroup> groups;
    };

    class ClashYamlImporter {
    public:
        // Загружает YAML и возвращает распарсенные proxies и proxy-groups
        static ClashDoc load_from_file(const std::string& path);

    private:
        static YAML::Node load_yaml(const std::string& path);

        // YAML merge key: <<: *anchor (может быть map или seq<map>)
        static YAML::Node normalize_merges(const YAML::Node& node);

        static Proxy parse_proxy(const YAML::Node& p);
        static ProxyGroup parse_group(const YAML::Node& g);

        static WarpCommon parse_wg_common(const YAML::Node& p);
        static std::optional<AmneziaWgOption> parse_awg(const YAML::Node& p);
    };

} // namespace proxycore::clash