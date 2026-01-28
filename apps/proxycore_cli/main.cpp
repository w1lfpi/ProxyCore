#include <iostream>
#include <string>

#include "proxycore/engine.hpp"
#include "proxycore/version.hpp"

static const char* state_to_str(proxycore::EngineState s) {
    switch (s) {
    case proxycore::EngineState::Stopped:  return "Stopped";
    case proxycore::EngineState::Starting: return "Starting";
    case proxycore::EngineState::Running:  return "Running";
    case proxycore::EngineState::Stopping: return "Stopping";
    default: return "?";
    }
}

int main(int argc, char** argv) {
    std::cout << "proxycore_cli v" << proxycore::kVersion << "\n";

    if (argc < 2) {
        std::cout << "Usage: proxycore_cli <config.json|config.yaml>\n";
        return 2;
    }

    proxycore::Engine engine;

    auto sub = engine.subscribe([](const proxycore::Event& ev) {
        if (const auto* s = std::get_if<proxycore::StateChanged>(&ev)) {
            std::cout << "[event] state: " << state_to_str(s->from) << " -> " << state_to_str(s->to) << "\n";
        }
        else if (const auto* e = std::get_if<proxycore::ErrorEvent>(&ev)) {
            std::cout << "[event] error: " << e->message << "\n";
        }
        else if (const auto* c = std::get_if<proxycore::ConfigLoaded>(&ev)) {
            std::cout << "[event] config loaded, active_profile=" << c->profile_id << "\n";
        }
        });

    proxycore::EngineOptions opts;
    opts.io_threads = 2;

    if (!engine.start(opts)) {
        std::cout << "Engine start failed\n";
        return 1;
    }

    if (!engine.load_config_file(argv[1])) {
        std::cout << "Config load failed\n";
        engine.stop();
        return 1;
    }

    std::cout << "Press ENTER to stop...\n";
    std::string line;
    std::getline(std::cin, line);

    engine.unsubscribe(sub);
    engine.stop();
    return 0;
}