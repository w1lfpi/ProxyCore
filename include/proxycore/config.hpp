#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace proxycore {

    enum class ProxyType : std::uint8_t {
        Direct = 0,
        Http,
        Socks5
    };

    struct ProxyNode {
        std::string id;
        ProxyType type = ProxyType::Direct;
        std::string host;
        std::uint16_t port = 0;
        std::string username;
        std::string password;
    };

    enum class RuleAction : std::uint8_t {
        Direct = 0,
        Proxy,
        Reject
    };

    struct DomainRule {
        std::string pattern;        // "example.com" или ".example.com"
        RuleAction action = RuleAction::Direct;
        std::string proxy_node_id;  // если action == Proxy
    };

    struct ConfigProfile {
        std::string id;
        std::vector<ProxyNode> nodes;
        std::vector<DomainRule> domain_rules;
    };

    // --- Inbounds ---
    struct Socks5Inbound {
        bool enabled = true;
        std::string bind = "127.0.0.1";
        std::uint16_t port = 1080;
    };

    struct TunInbound {
        bool enabled = false;
        std::string name = "proxycore-tun";
    };

    struct Inbounds {
        std::optional<Socks5Inbound> socks5;
        std::optional<TunInbound> tun;
    };

    struct Config {
        Inbounds inbounds;
        std::vector<ConfigProfile> profiles;
        std::string active_profile_id;
    };

    struct ConfigError {
        std::string message;
    };

} // namespace proxycore