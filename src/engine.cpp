#include "proxycore/engine.hpp"
#include "config_manager.hpp"
#include "net/socks5_server.hpp"
#include "pal/pal_factory.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cctype>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

namespace proxycore {

    struct Engine::Impl {
        std::atomic<EngineState> st{ EngineState::Stopped };
        std::mutex mtx;

        std::unique_ptr<boost::asio::io_context> ioc;
        std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work;
        std::vector<std::thread> threads;

        std::atomic<std::uint64_t> next_sub_id{ 1 };
        std::unordered_map<std::uint64_t, EventCallback> subs;

        ConfigManager cfg_mgr;
        Config cfg;

        std::shared_ptr<proxycore::net::Socks5Server> socks5;

        bool socks5_enabled = true;
        std::string socks5_bind = "127.0.0.1";
        std::uint16_t socks5_port = 1080;

        proxycore::pal::TunDevicePtr tun;
        bool tun_enabled = false;
        std::string tun_name = "proxycore-tun";

        void emit(Event ev) {
            if (ioc) {
                boost::asio::post(*ioc, [this, ev = std::move(ev)]() mutable {
                    std::unordered_map<std::uint64_t, EventCallback> copy;
                    {
                        std::lock_guard<std::mutex> lock(mtx);
                        copy = subs;
                    }
                    for (auto& [id, cb] : copy) {
                        try { cb(ev); }
                        catch (...) {}
                    }
                    });
            }
        }

        void change_state(EngineState to) {
            EngineState from = st.load(std::memory_order_relaxed);
            st.store(to, std::memory_order_relaxed);
            emit(StateChanged{ from, to });
        }

        static std::string to_lower(std::string s) {
            for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        }

        proxycore::net::Socks5Server::DecideFn make_route_decider_unlocked() {
            auto* impl_ptr = this;

            return [impl_ptr](const std::string& host, std::uint16_t port) -> proxycore::net::RouteDecision {
                const std::string h = Impl::to_lower(host);

                std::lock_guard<std::mutex> lock(impl_ptr->mtx);

                const std::string active_id = impl_ptr->cfg.active_profile_id;
                const ConfigProfile* active = nullptr;
                for (const auto& p : impl_ptr->cfg.profiles) {
                    if (p.id == active_id) { active = &p; break; }
                }

                proxycore::net::RouteDecision out;
                out.action = proxycore::net::RouteDecision::Action::Direct;

                if (!active) return out;

                auto ends_with = [](const std::string& s, const std::string& suf) -> bool {
                    if (s.size() < suf.size()) return false;
                    return std::equal(suf.rbegin(), suf.rend(), s.rbegin());
                    };

                auto find_node = [&](const std::string& node_id) -> const ProxyNode* {
                    for (const auto& n : active->nodes) {
                        if (n.id == node_id) return &n;
                    }
                    return nullptr;
                    };

                for (const auto& r : active->domain_rules) {
                    std::string pat = Impl::to_lower(r.pattern);
                    if (pat.empty()) continue;

                    bool match = false;

                    if (pat[0] == '.') {
                        const std::string base = pat.substr(1);
                        match = (h == base) || ends_with(h, pat);
                    }
                    else {
                        match = (h == pat) || ends_with(h, "." + pat);
                    }

                    if (!match) continue;

                    if (r.action == RuleAction::Reject) {
                        out.action = proxycore::net::RouteDecision::Action::Reject;
                        return out;
                    }

                    if (r.action == RuleAction::Direct) {
                        out.action = proxycore::net::RouteDecision::Action::Direct;
                        return out;
                    }

                    // Proxy
                    const std::string node_id = r.proxy_node_id;
                    const ProxyNode* node = find_node(node_id);
                    if (!node) {
                        out.action = proxycore::net::RouteDecision::Action::Reject;
                        return out;
                    }

                    if (node->type == ProxyType::Socks5) {
                        out.action = proxycore::net::RouteDecision::Action::ProxySocks5;
                        out.upstream_host = node->host;
                        out.upstream_port = node->port;
                        out.username = node->username;
                        out.password = node->password;
                        (void)port;
                        return out;
                    }

                    // пока поддерживаем только socks5 outbound
                    out.action = proxycore::net::RouteDecision::Action::Reject;
                    return out;
                }

                return out;
                };
        }

        void stop_socks5_unlocked() {
            if (socks5) {
                socks5->stop();
                socks5.reset();
            }
        }

        void stop_tun_unlocked() {
            if (tun) {
                tun->stop();
                tun.reset();
            }
        }

        void apply_tun_unlocked() {
            bool enabled = false;
            std::string name = "proxycore-tun";

            if (cfg.inbounds.tun.has_value()) {
                const auto& t = *cfg.inbounds.tun;
                enabled = t.enabled;
                name = t.name;
            }

            const bool params_changed = (enabled != tun_enabled) || (name != tun_name);
            tun_enabled = enabled;
            tun_name = name;

            const bool need_start = tun_enabled && !tun;
            const bool need_restart = tun && params_changed;
            const bool need_stop = !tun_enabled && tun;

            if (!need_start && !need_restart && !need_stop) return;

            stop_tun_unlocked();

            if (tun_enabled) {
                tun = proxycore::pal::PalFactory::create_tun();
                if (!tun) {
                    spdlog::warn("[engine] tun requested but not supported on this platform");
                    return;
                }

                proxycore::pal::TunConfig tc;
                tc.name = tun_name;

                if (!tun->start(tc)) {
                    spdlog::error("[engine] tun start failed");
                    tun.reset();
                    return;
                }

                spdlog::info("[engine] tun started (stub): name={}", tun_name);
            }
            else {
                spdlog::info("[engine] tun disabled");
            }
        }

        void apply_inbounds_unlocked() {
            bool enabled = true;
            std::string bind = "127.0.0.1";
            std::uint16_t port = 1080;

            if (cfg.inbounds.socks5.has_value()) {
                const auto& s = *cfg.inbounds.socks5;
                enabled = s.enabled;
                bind = s.bind;
                port = s.port;
            }

            const bool params_changed =
                (enabled != socks5_enabled) || (bind != socks5_bind) || (port != socks5_port);

            socks5_enabled = enabled;
            socks5_bind = bind;
            socks5_port = port;

            if (!ioc) return;

            const bool need_start = socks5_enabled && !socks5;
            const bool need_restart = socks5 && params_changed;
            const bool need_stop = !socks5_enabled && socks5;

            if (!need_start && !need_restart && !need_stop) return;

            stop_socks5_unlocked();

            if (socks5_enabled) {
                socks5 = std::make_shared<proxycore::net::Socks5Server>(
                    *ioc, socks5_bind, socks5_port, make_route_decider_unlocked()
                );
                socks5->start();
                spdlog::info("[engine] socks5 inbound started on {}:{}", socks5_bind, socks5_port);
            }
            else {
                spdlog::info("[engine] socks5 inbound disabled");
            }
        }
    };

    Engine::Engine() : impl_(std::make_unique<Impl>()) {}
    Engine::~Engine() { stop(); }

    bool Engine::start(const EngineOptions& opts) {
        EngineState expected = EngineState::Stopped;
        if (!impl_->st.compare_exchange_strong(expected, EngineState::Starting)) {
            return false;
        }

        try {
            impl_->ioc = std::make_unique<boost::asio::io_context>();
            impl_->work = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(
                impl_->ioc->get_executor()
            );

            const std::size_t n = (opts.io_threads == 0) ? 1 : opts.io_threads;
            impl_->threads.reserve(n);

            for (std::size_t i = 0; i < n; ++i) {
                impl_->threads.emplace_back([this]() {
                    try {
                        impl_->ioc->run();
                    }
                    catch (const std::exception& ex) {
                        impl_->emit(ErrorEvent{ std::string("io_context exception: ") + ex.what() });
                    }
                    });
            }

            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                impl_->apply_inbounds_unlocked();
                impl_->apply_tun_unlocked();
            }

            impl_->change_state(EngineState::Running);
            spdlog::info("proxycore started, io_threads={}", n);
            return true;
        }
        catch (const std::exception& ex) {
            impl_->emit(ErrorEvent{ std::string("start failed: ") + ex.what() });
            impl_->change_state(EngineState::Stopped);
            return false;
        }
    }

    void Engine::stop() {
        EngineState s = impl_->st.load(std::memory_order_relaxed);
        if (s == EngineState::Stopped) return;

        impl_->change_state(EngineState::Stopping);

        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            impl_->stop_socks5_unlocked();
            impl_->stop_tun_unlocked();
        }

        if (impl_->work) impl_->work->reset();
        if (impl_->ioc) impl_->ioc->stop();

        for (auto& t : impl_->threads) {
            if (t.joinable()) t.join();
        }

        impl_->threads.clear();
        impl_->ioc.reset();
        impl_->work.reset();

        impl_->change_state(EngineState::Stopped);
        spdlog::info("proxycore stopped");
    }

    bool Engine::load_config_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        Config tmp;

        if (auto err = impl_->cfg_mgr.load_from_file(path, tmp)) {
            impl_->emit(ErrorEvent{ err->message });
            return false;
        }

        impl_->cfg = std::move(tmp);
        impl_->emit(ConfigLoaded{ impl_->cfg.active_profile_id });

        impl_->apply_inbounds_unlocked();
        impl_->apply_tun_unlocked();
        return true;
    }

    bool Engine::load_config_text(const std::string& text, const std::string& format) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        Config tmp;

        if (auto err = impl_->cfg_mgr.load_from_text(text, format, tmp)) {
            impl_->emit(ErrorEvent{ err->message });
            return false;
        }

        impl_->cfg = std::move(tmp);
        impl_->emit(ConfigLoaded{ impl_->cfg.active_profile_id });

        impl_->apply_inbounds_unlocked();
        impl_->apply_tun_unlocked();
        return true;
    }

    bool Engine::set_active_profile(const std::string& profile_id) {
        std::lock_guard<std::mutex> lock(impl_->mtx);

        bool found = false;
        for (const auto& p : impl_->cfg.profiles) {
            if (p.id == profile_id) { found = true; break; }
        }

        if (!found) {
            impl_->emit(ErrorEvent{ "Профиль не найден: " + profile_id });
            return false;
        }

        impl_->cfg.active_profile_id = profile_id;
        impl_->emit(ConfigLoaded{ profile_id });

        // правила/узлы могли поменяться
        impl_->apply_inbounds_unlocked();
        impl_->apply_tun_unlocked();
        return true;
    }

    EngineState Engine::state() const {
        return impl_->st.load(std::memory_order_relaxed);
    }

    std::uint64_t Engine::subscribe(EventCallback cb) {
        if (!cb) return 0;
        const std::uint64_t id = impl_->next_sub_id.fetch_add(1);
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->subs.emplace(id, std::move(cb));
        return id;
    }

    void Engine::unsubscribe(std::uint64_t subscription_id) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->subs.erase(subscription_id);
    }

} // namespace proxycore