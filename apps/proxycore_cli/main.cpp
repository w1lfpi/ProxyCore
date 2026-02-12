#include <atomic>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#include <spdlog/spdlog.h>

#include "proxycore/engine.hpp"
#include "proxycore/version.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

static std::atomic_bool g_stop{ false };

static void request_stop() {
    g_stop.store(true, std::memory_order_relaxed);
}

static void on_signal(int) {
    request_stop();
}

#if defined(_WIN32)
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_LOGOFF_EVENT:
        request_stop();
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

static const char* state_to_str(proxycore::EngineState s) {
    switch (s) {
    case proxycore::EngineState::Stopped:  return "Stopped";
    case proxycore::EngineState::Starting: return "Starting";
    case proxycore::EngineState::Running:  return "Running";
    case proxycore::EngineState::Stopping: return "Stopping";
    default: return "?";
    }
}

static void print_help() {
    std::cout
        << "proxycore_cli v" << proxycore::kVersion << "\n"
        << "Usage:\n"
        << "  proxycore_cli --config <path> [--io-threads N] [--log-level L] [--daemon]\n"
        << "  proxycore_cli <config.json|config.yaml>\n"
        << "  proxycore_cli --help\n"
        << "  proxycore_cli --version\n"
        << "\n"
        << "Options:\n"
        << "  --config <path>       Path to config file (json/yaml)\n"
        << "  --io-threads <N>      IO threads (default: 2)\n"
        << "  --log-level <level>   trace|debug|info|warn|error|critical|off (default: info)\n"
        << "  --daemon              Run without waiting for ENTER (stop with Ctrl+C)\n"
        << "  --help, -h            Show this help\n"
        << "  --version, -v         Show version\n";
}

static bool is_flag(const std::string& s, const char* f) {
    return s == f;
}

static bool parse_log_level(const std::string& s, spdlog::level::level_enum& out) {
    if (s == "trace") { out = spdlog::level::trace; return true; }
    if (s == "debug") { out = spdlog::level::debug; return true; }
    if (s == "info") { out = spdlog::level::info;  return true; }
    if (s == "warn") { out = spdlog::level::warn;  return true; }
    if (s == "error") { out = spdlog::level::err;   return true; }
    if (s == "critical") { out = spdlog::level::critical; return true; }
    if (s == "off") { out = spdlog::level::off;   return true; }
    return false;
}

int main(int argc, char** argv) {
    // 1) Сначала — обработчики остановки (Ctrl+C)
    std::signal(SIGINT, on_signal);
#if defined(SIGTERM)
    std::signal(SIGTERM, on_signal);
#endif
#if defined(_WIN32)
    // Для Windows: корректно ловим Ctrl+C / закрытие консоли
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#endif

    // 2) РАННИЙ разбор аргументов (до engine.start / load_config)
    std::string config_path;
    std::size_t io_threads = 2;
    bool daemon = false;
    spdlog::level::level_enum log_level = spdlog::level::info;

    if (argc <= 1) {
        print_help();
        return 2;
    }

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (is_flag(a, "--help") || is_flag(a, "-h")) {
            print_help();
            return 0;
        }
        if (is_flag(a, "--version") || is_flag(a, "-v")) {
            std::cout << proxycore::kVersion << "\n";
            return 0;
        }
        if (is_flag(a, "--daemon")) {
            daemon = true;
            continue;
        }
        if (is_flag(a, "--config")) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --config requires a path\n";
                return 2;
            }
            config_path = argv[++i];
            continue;
        }
        if (is_flag(a, "--io-threads")) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --io-threads requires a number\n";
                return 2;
            }
            try {
                std::size_t v = static_cast<std::size_t>(std::stoul(argv[++i]));
                io_threads = (v == 0 ? 1 : v);
            }
            catch (...) {
                std::cerr << "Error: invalid --io-threads value\n";
                return 2;
            }
            continue;
        }
        if (is_flag(a, "--log-level")) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --log-level requires a value\n";
                return 2;
            }
            std::string lvl = argv[++i];
            if (!parse_log_level(lvl, log_level)) {
                std::cerr << "Error: invalid --log-level value: " << lvl << "\n";
                return 2;
            }
            continue;
        }

        // позиционный аргумент = config path
        if (config_path.empty()) {
            config_path = a;
        }
        else {
            std::cerr << "Error: unexpected argument: " << a << "\n";
            return 2;
        }
    }

    if (config_path.empty()) {
        std::cerr << "Error: config path is not specified\n";
        print_help();
        return 2;
    }

    // 3) Настраиваем логирование до старта движка
    spdlog::set_level(log_level);

    std::cout << "proxycore_cli v" << proxycore::kVersion << "\n";

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
    opts.io_threads = io_threads;

    if (!engine.load_config_file(config_path)) {
        std::cerr << "Config load failed: " << config_path << "\n";
        engine.unsubscribe(sub);
        return 1;
    }

    if (!engine.start(opts)) {
        std::cerr << "Engine start failed\n";
        engine.unsubscribe(sub);
        return 1;
    }

    if (!daemon) {
        std::cout << "Press ENTER to stop...\n";
        std::string line;
        std::getline(std::cin, line);
    }
    else {
        std::cout << "Running in daemon mode. Press Ctrl+C to stop...\n";
        while (!g_stop.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    engine.unsubscribe(sub);
    engine.stop();
    return 0;
}