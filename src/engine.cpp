#include "proxycore/engine.hpp"

#include "proxycore/config_manager.hpp"
#include "proxycore/tun/tun_inbound.hpp"
#include "net/socks5_server.hpp"
#include "pal/pal_factory.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <spdlog/spdlog.h>
namespace proxycore {

    static std::string to_lower_copy(std::string s) {
        for (char& c : s) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return s;
    }

    static std::string normalize_host(std::string s) {
        s = to_lower_copy(std::move(s));
        while (!s.empty() && s.back() == '.') {
            s.pop_back();
        }
        return s;
    }

    static bool ends_with(const std::string& s, const std::string& suf) {
        if (s.size() < suf.size()) {
            return false;
        }
        return std::equal(suf.rbegin(), suf.rend(), s.rbegin());
    }

    static bool match_rule(const DomainRule& r, const std::string& host_lc) {
        if (r.pattern.empty()) {
            return false;
        }

        if (r.match == DomainMatchType::Exact) {
            return host_lc == r.pattern;
        }

        if (host_lc == r.pattern) {
            return true;
        }

        const std::string dot_pat = std::string(".") + r.pattern;
        return ends_with(host_lc, dot_pat);
    }

    static const ConfigProfile* find_profile(const Config& cfg, const std::string& id) {
        for (const auto& p : cfg.profiles) {
            if (p.id == id) {
                return &p;
            }
        }
        return nullptr;
    }

    static const ProxyNode* find_node(const ConfigProfile& p, const std::string& id) {
        if (id.empty()) {
            return nullptr;
        }

        for (const auto& n : p.nodes) {
            if (n.id == id) {
                return &n;
            }
        }

        return nullptr;
    }

    struct Engine::Impl {
        boost::asio::io_context ioc;
        std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work;
        std::vector<std::thread> threads;
        std::mutex mu;

        Config cfg{};
        const ConfigProfile* active_profile = nullptr;

        std::shared_ptr<net::Socks5Server> socks5_server;
        std::shared_ptr<proxycore::tun::TunInbound> tun_inbound;

        EngineState state = EngineState::Stopped;

        std::uint64_t next_sub_id = 1;
        std::unordered_map<std::uint64_t, EventCallback> subscribers;

        void publish(const Event& ev) {
            for (auto& kv : subscribers) {
                if (kv.second) {
                    kv.second(ev);
                }
            }
        }

        void set_state(EngineState s) {
            if (state == s) {
                return;
            }

            const EngineState old = state;
            state = s;

            Event ev = StateChanged{ old, s };
            publish(ev);
        }

        net::RouteDecision decide_route(const std::string& host, std::uint16_t port) const {
            (void)port;

            net::RouteDecision d;
            d.action = net::RouteDecision::Action::Direct;

            if (!active_profile) {
                return d;
            }

            const std::string h = normalize_host(host);
            const DomainRule* matched = nullptr;

            for (const auto& r : active_profile->domain_rules) {
                if (match_rule(r, h)) {
                    matched = &r;
                    break;
                }
            }

            if (matched) {
                if (matched->action == RuleAction::Reject) {
                    d.action = net::RouteDecision::Action::Reject;
                    return d;
                }

                if (matched->action == RuleAction::Direct) {
                    d.action = net::RouteDecision::Action::Direct;
                    return d;
                }

                std::string node_id = matched->proxy_node_id;
                if (node_id.empty()) {
                    node_id = active_profile->default_outbound;
                }

                const ProxyNode* node = find_node(*active_profile, node_id);
                if (!node) {
                    spdlog::warn("[engine] rule matched but node not found: '{}', fallback DIRECT", node_id);
                    d.action = net::RouteDecision::Action::Direct;
                    return d;
                }

                if (node->type == ProxyType::Direct) {
                    d.action = net::RouteDecision::Action::Direct;
                    return d;
                }

                if (node->type == ProxyType::Socks5) {
                    d.action = net::RouteDecision::Action::ProxySocks5;
                    d.upstream_host = node->host;
                    d.upstream_port = node->port;
                    d.username = node->username;
                    d.password = node->password;
                    return d;
                }

                if (node->type == ProxyType::Http) {
                    d.action = net::RouteDecision::Action::ProxyHttpConnect;
                    d.upstream_host = node->host;
                    d.upstream_port = node->port;
                    d.username = node->username;
                    d.password = node->password;
                    return d;
                }

                d.action = net::RouteDecision::Action::Direct;
                return d;
            }

            if (!active_profile->default_outbound.empty()) {
                const ProxyNode* node = find_node(*active_profile, active_profile->default_outbound);

                if (node) {
                    if (node->type == ProxyType::Direct) {
                        d.action = net::RouteDecision::Action::Direct;
                        return d;
                    }

                    if (node->type == ProxyType::Socks5) {
                        d.action = net::RouteDecision::Action::ProxySocks5;
                        d.upstream_host = node->host;
                        d.upstream_port = node->port;
                        d.username = node->username;
                        d.password = node->password;
                        return d;
                    }

                    if (node->type == ProxyType::Http) {
                        d.action = net::RouteDecision::Action::ProxyHttpConnect;
                        d.upstream_host = node->host;
                        d.upstream_port = node->port;
                        d.username = node->username;
                        d.password = node->password;
                        return d;
                    }
                }
            }

            d.action = net::RouteDecision::Action::Direct;
            return d;
        }
    };

    Engine::Engine()
        : impl_(std::make_unique<Impl>()) {
    }

    Engine::~Engine() {
        stop();
    }

    bool Engine::start(const EngineOptions& opts) {
        std::lock_guard<std::mutex> lk(impl_->mu);

        if (impl_->state == EngineState::Running) {
            return true;
        }

        if (!impl_->active_profile) {
            spdlog::error("[engine] start failed: config not loaded / active profile not set");
            Event ev = ErrorEvent{ "start failed: config not loaded / active profile not set" };
            impl_->publish(ev);
            return false;
        }

        impl_->set_state(EngineState::Starting);

        impl_->work.emplace(boost::asio::make_work_guard(impl_->ioc));

        const std::size_t n = std::max<std::size_t>(1, opts.io_threads);
        impl_->threads.reserve(n);

        for (std::size_t i = 0; i < n; ++i) {
            impl_->threads.emplace_back([this]() {
                try {
                    impl_->ioc.run();
                }
                catch (const std::exception& ex) {
                    spdlog::error("[engine] io_context.run exception: {}", ex.what());
                }
                });
        }

        if (impl_->cfg.inbounds.socks5 && impl_->cfg.inbounds.socks5->enabled) {
            const std::string bind = impl_->cfg.inbounds.socks5->bind;
            const std::uint16_t port = impl_->cfg.inbounds.socks5->port;

            auto decide = [this](const std::string& host, std::uint16_t p) -> net::RouteDecision {
                std::lock_guard<std::mutex> lk2(impl_->mu);
                return impl_->decide_route(host, p);
                };

            impl_->socks5_server = std::make_shared<net::Socks5Server>(
                impl_->ioc,
                bind,
                port,
                decide
            );

            impl_->socks5_server->start();
            spdlog::info("[engine] socks5 inbound started on {}:{}", bind, port);
        }

        if (impl_->cfg.inbounds.tun && impl_->cfg.inbounds.tun->enabled) {
            pal::TunDevicePtr tun_dev = pal::PalFactory::create_tun();
            if (!tun_dev) {
                spdlog::error("[engine] TUN requested, but create_tun() returned null");
                Event ev = ErrorEvent{ "TUN requested, but create_tun() returned null" };
                impl_->publish(ev);
                return false;
            }

            proxycore::tun::TunInbound::Config tun_cfg;
            tun_cfg.name = impl_->cfg.inbounds.tun->name;
            tun_cfg.ipv4_addr = impl_->cfg.inbounds.tun->ipv4_addr;
            tun_cfg.ipv4_prefix = impl_->cfg.inbounds.tun->ipv4_prefix;

            impl_->tun_inbound = std::make_shared<proxycore::tun::TunInbound>(std::move(tun_dev));

            if (!impl_->tun_inbound->start(tun_cfg)) {
                spdlog::error(
                    "[engine] failed to start TUN inbound: name={}, ipv4={}/{}",
                    tun_cfg.name,
                    tun_cfg.ipv4_addr,
                    static_cast<int>(tun_cfg.ipv4_prefix)
                );
                Event ev = ErrorEvent{ "failed to start TUN inbound" };
                impl_->publish(ev);
                impl_->tun_inbound.reset();
                return false;
            }

            spdlog::info(
                "[engine] tun inbound started: name={}, ipv4={}/{}",
                tun_cfg.name,
                tun_cfg.ipv4_addr,
                static_cast<int>(tun_cfg.ipv4_prefix)
            );
        }

        impl_->set_state(EngineState::Running);
        return true;
    }

    void Engine::stop() {
        std::unique_lock<std::mutex> lk(impl_->mu);

        if (impl_->state == EngineState::Stopped) {
            return;
        }

        impl_->set_state(EngineState::Stopping);

        if (impl_->tun_inbound) {
            impl_->tun_inbound->stop();
            impl_->tun_inbound.reset();
        }

        if (impl_->socks5_server) {
            impl_->socks5_server->stop();
            impl_->socks5_server.reset();
        }

        if (impl_->work.has_value()) {
            impl_->work.reset();
        }

        impl_->ioc.stop();

        std::vector<std::thread> threads = std::move(impl_->threads);
        lk.unlock();

        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        lk.lock();
        impl_->ioc.restart();
        impl_->set_state(EngineState::Stopped);
    }

    bool Engine::load_config_file(const std::string& path) {
        Config cfg;
        ConfigManager cm;

        if (auto err = cm.load_from_file(path, cfg)) {
            spdlog::error("[engine] config error: {}", err->message);
            Event ev = ErrorEvent{ err->message };

            std::lock_guard<std::mutex> lk(impl_->mu);
            impl_->publish(ev);
            return false;
        }

        std::lock_guard<std::mutex> lk(impl_->mu);

        impl_->cfg = std::move(cfg);
        impl_->active_profile = find_profile(impl_->cfg, impl_->cfg.active_profile_id);

        if (!impl_->active_profile) {
            const std::string msg = "active_profile not found: " + impl_->cfg.active_profile_id;
            spdlog::error("[engine] {}", msg);
            Event ev = ErrorEvent{ msg };
            impl_->publish(ev);
            return false;
        }

        spdlog::info("[engine] config loaded, active_profile={}", impl_->cfg.active_profile_id);
        Event ev = ConfigLoaded{ impl_->cfg.active_profile_id };
        impl_->publish(ev);
        return true;
    }

    bool Engine::load_config_text(const std::string& text, const std::string& format) {
        Config cfg;
        ConfigManager cm;

        if (auto err = cm.load_from_text(text, format, cfg)) {
            spdlog::error("[engine] config error: {}", err->message);
            Event ev = ErrorEvent{ err->message };

            std::lock_guard<std::mutex> lk(impl_->mu);
            impl_->publish(ev);
            return false;
        }

        std::lock_guard<std::mutex> lk(impl_->mu);

        impl_->cfg = std::move(cfg);
        impl_->active_profile = find_profile(impl_->cfg, impl_->cfg.active_profile_id);

        if (!impl_->active_profile) {
            const std::string msg = "active_profile not found: " + impl_->cfg.active_profile_id;
            spdlog::error("[engine] {}", msg);
            Event ev = ErrorEvent{ msg };
            impl_->publish(ev);
            return false;
        }

        spdlog::info("[engine] config loaded, active_profile={}", impl_->cfg.active_profile_id);
        Event ev = ConfigLoaded{ impl_->cfg.active_profile_id };
        impl_->publish(ev);
        return true;
    }

    bool Engine::set_active_profile(const std::string& profile_id) {
        std::lock_guard<std::mutex> lk(impl_->mu);

        const ConfigProfile* p = find_profile(impl_->cfg, profile_id);
        if (!p) {
            return false;
        }

        impl_->cfg.active_profile_id = profile_id;
        impl_->active_profile = p;

        Event ev = ConfigLoaded{ profile_id };
        impl_->publish(ev);
        return true;
    }

    EngineState Engine::state() const {
        std::lock_guard<std::mutex> lk(impl_->mu);
        return impl_->state;
    }

    std::uint64_t Engine::subscribe(EventCallback cb) {
        std::lock_guard<std::mutex> lk(impl_->mu);
        const std::uint64_t id = impl_->next_sub_id++;
        impl_->subscribers.emplace(id, std::move(cb));
        return id;
    }

    void Engine::unsubscribe(std::uint64_t subscription_id) {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->subscribers.erase(subscription_id);
    }

} // namespace proxycore