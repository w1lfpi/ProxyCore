#include "config_manager.hpp"

#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

namespace proxycore {

    static ProxyType proxy_type_from_string(const std::string& s) {
        if (s == "direct") return ProxyType::Direct;
        if (s == "http") return ProxyType::Http;
        if (s == "socks5") return ProxyType::Socks5;
        return ProxyType::Direct;
    }

    static RuleAction rule_action_from_string(const std::string& s) {
        if (s == "direct") return RuleAction::Direct;
        if (s == "proxy") return RuleAction::Proxy;
        if (s == "reject") return RuleAction::Reject;
        return RuleAction::Direct;
    }

    std::optional<ConfigError> ConfigManager::load_from_file(const std::string& path, Config& out) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) {
            return ConfigError{ "Не удалось открыть конфиг: " + path };
        }
        std::ostringstream ss;
        ss << ifs.rdbuf();
        const std::string text = ss.str();

        const auto dot = path.find_last_of('.');
        std::string ext = (dot == std::string::npos) ? "" : path.substr(dot + 1);
        for (auto& c : ext) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));

        if (ext == "json") return load_from_text(text, "json", out);
        if (ext == "yml" || ext == "yaml") return load_from_text(text, "yaml", out);

        if (auto e = parse_json(text, out); !e.has_value()) return validate(out);
        if (auto e = parse_yaml(text, out); !e.has_value()) return validate(out);

        return ConfigError{ "Не удалось распознать формат конфига (ожидался .json/.yaml/.yml)" };
    }

    std::optional<ConfigError> ConfigManager::load_from_text(const std::string& text, const std::string& format, Config& out) {
        if (format == "json") {
            if (auto e = parse_json(text, out)) return e;
            return validate(out);
        }
        if (format == "yaml") {
            if (auto e = parse_yaml(text, out)) return e;
            return validate(out);
        }
        return ConfigError{ "Неизвестный формат: " + format };
    }

    std::optional<ConfigError> ConfigManager::parse_json(const std::string& text, Config& out) {
        try {
            using nlohmann::json;
            json j = json::parse(text);

            Config cfg;

            // inbounds
            if (j.contains("inbounds") && j["inbounds"].is_object()) {
                const auto& jin = j["inbounds"];

                if (jin.contains("socks5") && jin["socks5"].is_object()) {
                    Socks5Inbound s5;
                    const auto& js5 = jin["socks5"];
                    s5.enabled = js5.value("enabled", true);
                    s5.bind = js5.value("bind", std::string("127.0.0.1"));
                    s5.port = static_cast<std::uint16_t>(js5.value("port", 1080));
                    cfg.inbounds.socks5 = s5;
                }

                if (jin.contains("tun") && jin["tun"].is_object()) {
                    TunInbound t;
                    const auto& jt = jin["tun"];
                    t.enabled = jt.value("enabled", false);
                    t.name = jt.value("name", std::string("proxycore-tun"));
                    cfg.inbounds.tun = t;
                }
            }

            cfg.active_profile_id = j.value("active_profile", "");

            if (j.contains("profiles") && j["profiles"].is_array()) {
                for (const auto& jp : j["profiles"]) {
                    ConfigProfile p;
                    p.id = jp.value("id", "");

                    if (jp.contains("nodes") && jp["nodes"].is_array()) {
                        for (const auto& jn : jp["nodes"]) {
                            ProxyNode n;
                            n.id = jn.value("id", "");
                            n.type = proxy_type_from_string(jn.value("type", "direct"));
                            n.host = jn.value("host", "");
                            n.port = static_cast<std::uint16_t>(jn.value("port", 0));
                            n.username = jn.value("username", "");
                            n.password = jn.value("password", "");
                            p.nodes.push_back(std::move(n));
                        }
                    }

                    if (jp.contains("rules") && jp["rules"].is_array()) {
                        for (const auto& jr : jp["rules"]) {
                            DomainRule r;
                            r.pattern = jr.value("domain", "");
                            r.action = rule_action_from_string(jr.value("action", "direct"));
                            r.proxy_node_id = jr.value("node", "");
                            p.domain_rules.push_back(std::move(r));
                        }
                    }

                    cfg.profiles.push_back(std::move(p));
                }
            }

            out = std::move(cfg);
            return std::nullopt;
        }
        catch (const std::exception& ex) {
            return ConfigError{ std::string("JSON parse error: ") + ex.what() };
        }
    }

    std::optional<ConfigError> ConfigManager::parse_yaml(const std::string& text, Config& out) {
        try {
            YAML::Node root = YAML::Load(text);

            Config cfg;

            // inbounds
            if (root["inbounds"] && root["inbounds"].IsMap()) {
                auto inb = root["inbounds"];

                if (inb["socks5"] && inb["socks5"].IsMap()) {
                    Socks5Inbound s5;
                    auto s = inb["socks5"];
                    if (s["enabled"]) s5.enabled = s["enabled"].as<bool>();
                    if (s["bind"]) s5.bind = s["bind"].as<std::string>();
                    if (s["port"]) s5.port = static_cast<std::uint16_t>(s["port"].as<int>());
                    cfg.inbounds.socks5 = s5;
                }

                if (inb["tun"] && inb["tun"].IsMap()) {
                    TunInbound t;
                    auto tn = inb["tun"];
                    if (tn["enabled"]) t.enabled = tn["enabled"].as<bool>();
                    if (tn["name"]) t.name = tn["name"].as<std::string>();
                    cfg.inbounds.tun = t;
                }
            }

            if (root["active_profile"]) cfg.active_profile_id = root["active_profile"].as<std::string>();

            if (root["profiles"] && root["profiles"].IsSequence()) {
                for (const auto& yp : root["profiles"]) {
                    ConfigProfile p;
                    if (yp["id"]) p.id = yp["id"].as<std::string>();

                    if (yp["nodes"] && yp["nodes"].IsSequence()) {
                        for (const auto& yn : yp["nodes"]) {
                            ProxyNode n;
                            if (yn["id"]) n.id = yn["id"].as<std::string>();
                            if (yn["type"]) n.type = proxy_type_from_string(yn["type"].as<std::string>());
                            if (yn["host"]) n.host = yn["host"].as<std::string>();
                            if (yn["port"]) n.port = static_cast<std::uint16_t>(yn["port"].as<int>());
                            if (yn["username"]) n.username = yn["username"].as<std::string>();
                            if (yn["password"]) n.password = yn["password"].as<std::string>();
                            p.nodes.push_back(std::move(n));
                        }
                    }

                    if (yp["rules"] && yp["rules"].IsSequence()) {
                        for (const auto& yr : yp["rules"]) {
                            DomainRule r;
                            if (yr["domain"]) r.pattern = yr["domain"].as<std::string>();
                            if (yr["action"]) r.action = rule_action_from_string(yr["action"].as<std::string>());
                            if (yr["node"]) r.proxy_node_id = yr["node"].as<std::string>();
                            p.domain_rules.push_back(std::move(r));
                        }
                    }

                    cfg.profiles.push_back(std::move(p));
                }
            }

            out = std::move(cfg);
            return std::nullopt;
        }
        catch (const std::exception& ex) {
            return ConfigError{ std::string("YAML parse error: ") + ex.what() };
        }
    }

    std::optional<ConfigError> ConfigManager::validate(const Config& cfg) {
        // socks5 inbound validation
        if (cfg.inbounds.socks5.has_value()) {
            const auto& s5 = *cfg.inbounds.socks5;
            if (s5.enabled && s5.port == 0) {
                return ConfigError{ "inbounds.socks5.port не может быть 0" };
            }
            if (s5.enabled && s5.bind.empty()) {
                return ConfigError{ "inbounds.socks5.bind пустой" };
            }
        }

        // tun inbound validation
        if (cfg.inbounds.tun.has_value()) {
            const auto& t = *cfg.inbounds.tun;
            if (t.enabled && t.name.empty()) {
                return ConfigError{ "inbounds.tun.name пустой" };
            }
        }

        if (cfg.profiles.empty()) {
            return ConfigError{ "В конфиге нет profiles" };
        }
        if (cfg.active_profile_id.empty()) {
            return ConfigError{ "Не задан active_profile" };
        }

        bool found = false;
        for (const auto& p : cfg.profiles) {
            if (p.id.empty()) return ConfigError{ "У профиля отсутствует id" };
            if (p.id == cfg.active_profile_id) found = true;
        }
        if (!found) {
            return ConfigError{ "active_profile не найден среди profiles" };
        }

        return std::nullopt;
    }

} // namespace proxycore