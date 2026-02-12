#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace proxycore::net {

    class HttpConnectClient : public std::enable_shared_from_this<HttpConnectClient> {
    public:
        using tcp = boost::asio::ip::tcp;
        using Done = std::function<void(const boost::system::error_code&)>;

        HttpConnectClient(
            tcp::socket& sock,
            tcp::resolver& resolver,
            std::string upstream_host,
            std::uint16_t upstream_port,
            std::string dst_host,
            std::uint16_t dst_port,
            std::string username,
            std::string password
        );

        void start(Done done);

    private:
        void resolve_upstream();
        void connect_upstream(const tcp::resolver::results_type& res);

        void send_connect_request();
        void read_until_headers_end();
        void parse_and_finish();

        void fail(const boost::system::error_code& ec);

        static std::string base64_encode(const std::string& in);

    private:
        tcp::socket& sock_;
        tcp::resolver& resolver_;

        std::string upstream_host_;
        std::uint16_t upstream_port_ = 0;

        std::string dst_host_;
        std::uint16_t dst_port_ = 0;

        std::string username_;
        std::string password_;

        Done done_;
        std::vector<std::uint8_t> outbuf_;

        boost::asio::streambuf inbuf_;
    };

} // namespace proxycore::net