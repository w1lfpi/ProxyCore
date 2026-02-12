#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "proxycore/config.hpp"
#include "proxycore/events.hpp"

namespace proxycore {

    struct EngineOptions {
        std::size_t io_threads = 1;
    };

    class Engine {
    public:
        using EventCallback = std::function<void(const Event&)>;

        Engine();
        ~Engine();

        Engine(const Engine&) = delete;
        Engine& operator=(const Engine&) = delete;

        bool start(const EngineOptions& opts = {});
        void stop();

        bool load_config_file(const std::string& path);
        bool load_config_text(const std::string& text, const std::string& format);

        bool set_active_profile(const std::string& profile_id);

        EngineState state() const;

        std::uint64_t subscribe(EventCallback cb);
        void unsubscribe(std::uint64_t subscription_id);

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace proxycore