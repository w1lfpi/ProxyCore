#pragma once

#include <boost/asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace proxycore::net {

    struct RouteDecision {
        enum class Action {
            Direct,
            Reject,
            ProxySocks5,
            ProxyHttpConnect
        };

        Action action = Action::Direct;

        std::string upstream_host;
        std::uint16_t upstream_port = 0;

        std::string username;
        std::string password;
    };

    class Socks5Server : public std::enable_shared_from_this<Socks5Server> {
    public:
        using DecideFn = std::function<RouteDecision(const std::string& host, std::uint16_t port)>;
        using tcp = boost::asio::ip::tcp;

        Socks5Server(boost::asio::io_context& ioc, std::string bind_ip, std::uint16_t port, DecideFn decide);

        void start();
        void stop();

    private:
        void do_accept();

    private:
        boost::asio::io_context& ioc_;
        tcp::acceptor acceptor_;
        std::string bind_ip_;
        std::uint16_t port_;
        DecideFn decide_;
    };

} // namespace proxycore::net