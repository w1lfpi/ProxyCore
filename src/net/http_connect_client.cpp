#include "http_connect_client.hpp"

#include <sstream>

namespace proxycore::net {

    HttpConnectClient::HttpConnectClient(
        tcp::socket& sock,
        tcp::resolver& resolver,
        std::string upstream_host,
        std::uint16_t upstream_port,
        std::string dst_host,
        std::uint16_t dst_port,
        std::string username,
        std::string password
    )
        : sock_(sock)
        , resolver_(resolver)
        , upstream_host_(std::move(upstream_host))
        , upstream_port_(upstream_port)
        , dst_host_(std::move(dst_host))
        , dst_port_(dst_port)
        , username_(std::move(username))
        , password_(std::move(password)) {
    }

    void HttpConnectClient::start(Done done) {
        done_ = std::move(done);
        resolve_upstream();
    }

    void HttpConnectClient::resolve_upstream() {
        auto self = shared_from_this();
        resolver_.async_resolve(upstream_host_, std::to_string(upstream_port_),
            [this, self](const boost::system::error_code& ec, tcp::resolver::results_type res) {
                if (ec) return fail(ec);
                connect_upstream(res);
            });
    }

    void HttpConnectClient::connect_upstream(const tcp::resolver::results_type& res) {
        auto self = shared_from_this();
        boost::asio::async_connect(sock_, res,
            [this, self](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) return fail(ec);
                send_connect_request();
            });
    }

    void HttpConnectClient::send_connect_request() {
        std::ostringstream req;

        req << "CONNECT " << dst_host_ << ":" << dst_port_ << " HTTP/1.1\r\n";
        req << "Host: " << dst_host_ << ":" << dst_port_ << "\r\n";
        req << "Proxy-Connection: Keep-Alive\r\n";

        const bool want_auth = !username_.empty() || !password_.empty();
        if (want_auth) {
            const std::string token = username_ + ":" + password_;
            req << "Proxy-Authorization: Basic " << base64_encode(token) << "\r\n";
        }

        req << "\r\n";

        const std::string s = req.str();
        outbuf_.assign(s.begin(), s.end());

        auto self = shared_from_this();
        boost::asio::async_write(sock_, boost::asio::buffer(outbuf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                read_until_headers_end();
            });
    }

    void HttpConnectClient::read_until_headers_end() {
        auto self = shared_from_this();
        boost::asio::async_read_until(sock_, inbuf_, "\r\n\r\n",
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                parse_and_finish();
            });
    }

    void HttpConnectClient::parse_and_finish() {
        std::istream is(&inbuf_);

        std::string httpver;
        unsigned code = 0;
        std::string reason;

        is >> httpver >> code;
        std::getline(is, reason); // остаток строки

        if (httpver.rfind("HTTP/", 0) != 0) {
            return fail(boost::asio::error::operation_not_supported);
        }
        if (code != 200) {
            return fail(boost::asio::error::access_denied);
        }

        // заголовки нам не важны, но мы их уже считали до \r\n\r\n
        done_({});
    }

    void HttpConnectClient::fail(const boost::system::error_code& ec) {
        if (done_) done_(ec);
    }

    std::string HttpConnectClient::base64_encode(const std::string& in) {
        static const char* tbl =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string out;
        out.reserve(((in.size() + 2) / 3) * 4);

        std::size_t i = 0;
        while (i < in.size()) {
            const unsigned b0 = static_cast<unsigned char>(in[i++]);
            const unsigned b1 = (i < in.size()) ? static_cast<unsigned char>(in[i++]) : 0U;
            const unsigned b2 = (i < in.size()) ? static_cast<unsigned char>(in[i++]) : 0U;

            const unsigned triple = (b0 << 16) | (b1 << 8) | b2;

            out.push_back(tbl[(triple >> 18) & 0x3F]);
            out.push_back(tbl[(triple >> 12) & 0x3F]);
            out.push_back((i - 1 < in.size() + 1) ? tbl[(triple >> 6) & 0x3F] : '=');
            out.push_back((i - 0 < in.size() + 1) ? tbl[(triple >> 0) & 0x3F] : '=');
        }

        // корректируем '=' по фактическому остатку
        const std::size_t mod = in.size() % 3;
        if (mod == 1) {
            out[out.size() - 1] = '=';
            out[out.size() - 2] = '=';
        }
        else if (mod == 2) {
            out[out.size() - 1] = '=';
        }

        return out;
    }

} // namespace proxycore::net