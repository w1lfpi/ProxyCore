#pragma once
#include <cstdint>
#include <string>
#include <variant>

namespace proxycore {

    enum class EngineState : std::uint8_t {
        Stopped = 0,
        Starting,
        Running,
        Stopping
    };

    struct StateChanged {
        EngineState from;
        EngineState to;
    };

    struct ErrorEvent {
        std::string message;
    };

    struct ConfigLoaded {
        std::string profile_id;
    };

    using Event = std::variant<StateChanged, ErrorEvent, ConfigLoaded>;

} // namespace proxycore