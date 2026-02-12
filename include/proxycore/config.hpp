#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace proxycore {

    enum class ProxyType {
        Direct,
        Socks5,
        Http
    };

    enum class RuleAction {
        Direct,
        Proxy,
        Reject
    };

    enum class DomainMatchType {
        Exact,   // domain
        Suffix   // domain_suffix
    };

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

    struct ProxyNode {
        std::string id;
        ProxyType type = ProxyType::Direct;

        // socks5/http
        std::string host;
        std::uint16_t port = 0;

        // auth (socks5 user/pass; http basic)
        std::string username;
        std::string password;
    };

    struct DomainRule {
        DomainMatchType match = DomainMatchType::Exact;
        std::string pattern;          // domain OR suffix (без ведущей точки)
        RuleAction action = RuleAction::Direct;

        // если action=proxy: можно указать конкретную ноду
        // если пусто -> берём profile.default_outbound
        std::string proxy_node_id;
    };

    struct ConfigProfile {
        std::string id;

        // default_outbound — строка id ноды
        std::string default_outbound;

        std::vector<ProxyNode> nodes;
        std::vector<DomainRule> domain_rules;
    };

    struct Config {
        Inbounds inbounds;

        std::string active_profile_id;
        std::vector<ConfigProfile> profiles;
    };

    struct ConfigError {
        std::string message;
    };

} // namespace proxycore