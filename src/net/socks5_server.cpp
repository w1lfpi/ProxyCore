#include "socks5_server.hpp"
#include "tcp_relay.hpp"
#include "socks5_client.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

namespace proxycore::net {

    namespace {
        constexpr std::uint8_t kSocksVer = 0x05;
        constexpr std::uint8_t kCmdConnect = 0x01;

        constexpr std::uint8_t kAtypIPv4 = 0x01;
        constexpr std::uint8_t kAtypDomain = 0x03;
        constexpr std::uint8_t kAtypIPv6 = 0x04;

        constexpr std::uint8_t kAuthNone = 0x00;
        constexpr std::uint8_t kAuthNoAcceptable = 0xFF;

        static std::string safe_remote_endpoint_str(boost::asio::ip::tcp::socket& s) {
            boost::system::error_code ec;
            auto ep = s.remote_endpoint(ec);
            if (ec) return "<unknown>";
            return ep.address().to_string() + ":" + std::to_string(ep.port());
        }

        struct Session : std::enable_shared_from_this<Session> {
            using tcp = boost::asio::ip::tcp;

            tcp::socket client;
            tcp::socket remote;     // либо direct dst, либо upstream socks5 tunnel
            tcp::resolver resolver; // используем и для direct resolve, и для upstream resolve

            Socks5Server::DecideFn decide;

            std::array<std::uint8_t, 512> buf{};

            // Для логов
            std::string dst_host;
            std::uint16_t dst_port = 0;

            explicit Session(boost::asio::io_context& ioc, tcp::socket c, Socks5Server::DecideFn d)
                : client(std::move(c)), remote(ioc), resolver(ioc), decide(std::move(d)) {
            }

            void start() {
                spdlog::info("[socks5] client connected: {}", safe_remote_endpoint_str(client));
                read_greeting();
            }

            void read_greeting() {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), 2),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }
                        if (buf[0] != kSocksVer) { close(); return; }
                        const std::size_t nmethods = buf[1];
                        read_methods(nmethods);
                    });
            }

            void read_methods(std::size_t n) {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), n),
                    [this, self, n](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }
                        bool has_none = false;
                        for (std::size_t i = 0; i < n; ++i) {
                            if (buf[i] == kAuthNone) { has_none = true; break; }
                        }

                        std::array<std::uint8_t, 2> resp{ kSocksVer, has_none ? kAuthNone : kAuthNoAcceptable };

                        boost::asio::async_write(client, boost::asio::buffer(resp),
                            [this, self, has_none](const boost::system::error_code& ec2, std::size_t) {
                                if (ec2) { close(); return; }
                                if (!has_none) { close(); return; }
                                read_request_header();
                            });
                    });
            }

            void read_request_header() {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), 4),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }
                        if (buf[0] != kSocksVer) { close(); return; }

                        const std::uint8_t cmd = buf[1];
                        const std::uint8_t atyp = buf[3];

                        if (cmd != kCmdConnect) {
                            spdlog::warn("[socks5] unsupported cmd={} from {}", (int)cmd, safe_remote_endpoint_str(client));
                            reply_fail(0x07); // Command not supported
                            return;
                        }

                        read_dst(atyp);
                    });
            }

            void read_dst(std::uint8_t atyp) {
                if (atyp == kAtypIPv4) read_ipv4();
                else if (atyp == kAtypIPv6) read_ipv6();
                else if (atyp == kAtypDomain) read_domain_len();
                else {
                    spdlog::warn("[socks5] unsupported atyp={} from {}", (int)atyp, safe_remote_endpoint_str(client));
                    reply_fail(0x08); // Address type not supported
                }
            }

            // IP-цели пока считаем DIRECT (для “как Clash” позже добавим правила на IP/CIDR)
            void read_ipv4() {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), 6),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }

                        boost::asio::ip::address_v4::bytes_type a{};
                        std::memcpy(a.data(), buf.data(), 4);
                        dst_port = (static_cast<std::uint16_t>(buf[4]) << 8) | buf[5];
                        dst_host = boost::asio::ip::address_v4(a).to_string();

                        spdlog::info("[socks5] CONNECT {}:{} (ipv4) from {}", dst_host, dst_port, safe_remote_endpoint_str(client));
                        connect_ip(boost::asio::ip::address_v4(a), dst_port);
                    });
            }

            void read_ipv6() {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), 18),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }

                        boost::asio::ip::address_v6::bytes_type a{};
                        std::memcpy(a.data(), buf.data(), 16);
                        dst_port = (static_cast<std::uint16_t>(buf[16]) << 8) | buf[17];
                        dst_host = boost::asio::ip::address_v6(a).to_string();

                        spdlog::info("[socks5] CONNECT {}:{} (ipv6) from {}", dst_host, dst_port, safe_remote_endpoint_str(client));
                        connect_ip(boost::asio::ip::address_v6(a), dst_port);
                    });
            }

            void read_domain_len() {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), 1),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }
                        const std::size_t len = buf[0];
                        read_domain_and_port(len);
                    });
            }

            void read_domain_and_port(std::size_t len) {
                auto self = shared_from_this();
                boost::asio::async_read(client, boost::asio::buffer(buf.data(), len + 2),
                    [this, self, len](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }

                        dst_host.assign(reinterpret_cast<char*>(buf.data()),
                            reinterpret_cast<char*>(buf.data() + len));
                        dst_port = (static_cast<std::uint16_t>(buf[len]) << 8) | buf[len + 1];

                        spdlog::info("[socks5] CONNECT {}:{} (domain) from {}", dst_host, dst_port, safe_remote_endpoint_str(client));

                        RouteDecision d;
                        if (decide) d = decide(dst_host, dst_port);

                        if (d.action == RouteDecision::Action::Reject) {
                            spdlog::info("[socks5] blocked by rules: {}:{}", dst_host, dst_port);
                            reply_fail(0x02); // connection not allowed by ruleset
                            return;
                        }

                        if (d.action == RouteDecision::Action::ProxySocks5) {
                            spdlog::info("[socks5] outbound via upstream socks5 {}:{} -> {}:{}",
                                d.upstream_host, d.upstream_port, dst_host, dst_port);
                            connect_via_upstream_socks5(std::move(d));
                            return;
                        }

                        // Direct
                        connect_domain(dst_host, dst_port);
                    });
            }

            void connect_via_upstream_socks5(RouteDecision d) {
                auto self = shared_from_this();

                auto cli = std::make_shared<Socks5Client>(
                    remote,
                    resolver,
                    d.upstream_host,
                    d.upstream_port,
                    dst_host,
                    dst_port,
                    d.username,
                    d.password
                );

                cli->start([this, self](const boost::system::error_code& ec) {
                    if (ec) {
                        spdlog::warn("[socks5] upstream socks5 failed {}:{} err={}", dst_host, dst_port, ec.message());
                        reply_fail(0x01); // general SOCKS server failure
                        return;
                    }

                    spdlog::info("[socks5] upstream tunnel ready {}:{}", dst_host, dst_port);
                    reply_success_and_relay();
                    });
            }

            void connect_domain(const std::string& host, std::uint16_t port) {
                auto self = shared_from_this();
                resolver.async_resolve(host, std::to_string(port),
                    [this, self, host, port](const boost::system::error_code& ec, tcp::resolver::results_type results) {
                        if (ec) {
                            spdlog::warn("[socks5] resolve failed {}:{} err={}", host, port, ec.message());
                            reply_fail(0x04); // Host unreachable
                            return;
                        }

                        boost::asio::async_connect(remote, results,
                            [this, self, host, port](const boost::system::error_code& ec2, const tcp::endpoint& ep) {
                                if (ec2) {
                                    spdlog::warn("[socks5] connect failed {}:{} err={}", host, port, ec2.message());
                                    reply_fail(0x05); // Connection refused / general fail
                                    return;
                                }

                                spdlog::info("[socks5] connected {}:{} -> {}:{}",
                                    host, port, ep.address().to_string(), ep.port());
                                reply_success_and_relay();
                            });
                    });
            }

            void connect_ip(const boost::asio::ip::address& addr, std::uint16_t port) {
                auto self = shared_from_this();
                tcp::endpoint ep(addr, port);

                remote.async_connect(ep, [this, self, addr, port](const boost::system::error_code& ec) {
                    if (ec) {
                        spdlog::warn("[socks5] connect failed {}:{} err={}", addr.to_string(), port, ec.message());
                        reply_fail(0x05);
                        return;
                    }

                    spdlog::info("[socks5] connected {}:{}", addr.to_string(), port);
                    reply_success_and_relay();
                    });
            }

            void reply_success_and_relay() {
                // VER REP RSV ATYP BND.ADDR BND.PORT
                // 0.0.0.0:0 достаточно для большинства клиентов
                std::array<std::uint8_t, 10> resp{};
                resp[0] = kSocksVer;
                resp[1] = 0x00; // succeeded
                resp[2] = 0x00; // rsv
                resp[3] = kAtypIPv4;

                auto self = shared_from_this();
                boost::asio::async_write(client, boost::asio::buffer(resp),
                    [this, self](const boost::system::error_code& ec, std::size_t) {
                        if (ec) { close(); return; }

                        auto relay = std::make_shared<TcpRelay>(
                            std::move(client), std::move(remote),
                            std::chrono::seconds(120) // как ты решил оставить
                        );
                        relay->start();
                    });
            }

            void reply_fail(std::uint8_t rep) {
                std::array<std::uint8_t, 10> resp{};
                resp[0] = kSocksVer;
                resp[1] = rep;
                resp[2] = 0x00;
                resp[3] = kAtypIPv4;

                auto self = shared_from_this();
                boost::asio::async_write(client, boost::asio::buffer(resp),
                    [this, self](const boost::system::error_code&, std::size_t) {
                        close();
                    });
            }

            void close() {
                boost::system::error_code ig;
                client.close(ig);
                remote.close(ig);
            }
        };

    } // namespace

    Socks5Server::Socks5Server(boost::asio::io_context& ioc,
        std::string bind_ip,
        std::uint16_t port,
        DecideFn decide)
        : ioc_(ioc),
        acceptor_(ioc),
        bind_ip_(std::move(bind_ip)),
        port_(port),
        decide_(std::move(decide)) {
    }

    void Socks5Server::start() {
        boost::system::error_code ec;

        auto addr = boost::asio::ip::make_address(bind_ip_, ec);
        if (ec) addr = boost::asio::ip::address_v4::loopback();

        tcp::endpoint ep(addr, port_);

        acceptor_.open(ep.protocol(), ec);
        if (ec) { spdlog::error("[socks5] acceptor open failed: {}", ec.message()); return; }

        acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
        if (ec) { spdlog::error("[socks5] bind {}:{} failed: {}", addr.to_string(), port_, ec.message()); return; }

        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) { spdlog::error("[socks5] listen failed: {}", ec.message()); return; }

        spdlog::info("[socks5] listening on {}:{}", addr.to_string(), port_);
        do_accept();
    }

    void Socks5Server::stop() {
        boost::system::error_code ec;
        acceptor_.close(ec);
        if (ec) spdlog::warn("[socks5] stop/close acceptor: {}", ec.message());
        else spdlog::info("[socks5] stopped");
    }

    void Socks5Server::do_accept() {
        auto self = shared_from_this();
        acceptor_.async_accept(
            [this, self](const boost::system::error_code& ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(ioc_, std::move(socket), decide_)->start();
                }
                else {
                    if (acceptor_.is_open()) spdlog::warn("[socks5] accept failed: {}", ec.message());
                }

                if (acceptor_.is_open()) do_accept();
            });
    }

} // namespace proxycore::net