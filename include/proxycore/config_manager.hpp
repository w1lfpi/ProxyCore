#pragma once
#include <optional>
#include <string>

#include "proxycore/config.hpp"

namespace proxycore {

    class ConfigManager {
    public:
        std::optional<ConfigError> load_from_file(const std::string& path, Config& out);
        std::optional<ConfigError> load_from_text(const std::string& text, const std::string& format, Config& out);

    private:
        std::optional<ConfigError> parse_json(const std::string& text, Config& out);
        std::optional<ConfigError> parse_yaml(const std::string& text, Config& out);
        std::optional<ConfigError> validate(const Config& cfg);
    };

} // namespace proxycore