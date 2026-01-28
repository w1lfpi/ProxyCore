#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace proxycore::net {

    class Socks5Client : public std::enable_shared_from_this<Socks5Client> {
    public:
        using tcp = boost::asio::ip::tcp;
        using Done = std::function<void(const boost::system::error_code&)>;

        Socks5Client(tcp::socket& sock,
            tcp::resolver& resolver,
            std::string upstream_host,
            std::uint16_t upstream_port,
            std::string dst_host,
            std::uint16_t dst_port,
            std::string username,
            std::string password);

        void start(Done done);

    private:
        void resolve_upstream();
        void connect_upstream(const tcp::resolver::results_type& res);

        void send_greeting();
        void read_method();
        void auth_username_password();

        void send_connect_request();
        void read_connect_reply_header();
        void read_connect_reply_rest(std::uint8_t atyp);

        void fail(const boost::system::error_code& ec);

        tcp::socket& sock_;
        tcp::resolver& resolver_;
        Done done_;

        std::string upstream_host_;
        std::uint16_t upstream_port_{ 0 };

        std::string dst_host_;
        std::uint16_t dst_port_{ 0 };

        std::string username_;
        std::string password_;

        std::vector<std::uint8_t> buf_;
    };

} // namespace proxycore::net