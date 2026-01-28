#include "socks5_client.hpp"

#include <array>

namespace proxycore::net {

    static constexpr std::uint8_t kVer = 0x05;
    static constexpr std::uint8_t kCmdConnect = 0x01;

    static constexpr std::uint8_t kAuthNone = 0x00;
    static constexpr std::uint8_t kAuthUserPass = 0x02;
    static constexpr std::uint8_t kAuthNoAcceptable = 0xFF;

    // RFC 1929
    static constexpr std::uint8_t kAuthVer = 0x01;

    static constexpr std::uint8_t kAtypIPv4 = 0x01;
    static constexpr std::uint8_t kAtypDomain = 0x03;
    static constexpr std::uint8_t kAtypIPv6 = 0x04;

    Socks5Client::Socks5Client(tcp::socket& sock,
        tcp::resolver& resolver,
        std::string upstream_host,
        std::uint16_t upstream_port,
        std::string dst_host,
        std::uint16_t dst_port,
        std::string username,
        std::string password)
        : sock_(sock)
        , resolver_(resolver)
        , upstream_host_(std::move(upstream_host))
        , upstream_port_(upstream_port)
        , dst_host_(std::move(dst_host))
        , dst_port_(dst_port)
        , username_(std::move(username))
        , password_(std::move(password)) {
    }

    void Socks5Client::start(Done done) {
        done_ = std::move(done);
        resolve_upstream();
    }

    void Socks5Client::resolve_upstream() {
        auto self = shared_from_this();
        resolver_.async_resolve(upstream_host_, std::to_string(upstream_port_),
            [this, self](const boost::system::error_code& ec, tcp::resolver::results_type res) {
                if (ec) return fail(ec);
                connect_upstream(res);
            });
    }

    void Socks5Client::connect_upstream(const tcp::resolver::results_type& res) {
        auto self = shared_from_this();
        boost::asio::async_connect(sock_, res,
            [this, self](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) return fail(ec);
                send_greeting();
            });
    }

    void Socks5Client::send_greeting() {
        // VER, NMETHODS, METHODS...
        const bool want_auth = !username_.empty() || !password_.empty();
        buf_.clear();
        buf_.push_back(kVer);
        buf_.push_back(want_auth ? 2 : 1);
        buf_.push_back(kAuthNone);
        if (want_auth) buf_.push_back(kAuthUserPass);

        auto self = shared_from_this();
        boost::asio::async_write(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                read_method();
            });
    }

    void Socks5Client::read_method() {
        auto self = shared_from_this();
        buf_.assign(2, 0);

        boost::asio::async_read(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                if (buf_[0] != kVer) {
                    return fail(boost::asio::error::operation_not_supported);
                }

                const std::uint8_t method = buf_[1];
                if (method == kAuthNone) {
                    send_connect_request();
                    return;
                }
                if (method == kAuthUserPass) {
                    auth_username_password();
                    return;
                }
                // no acceptable methods
                fail(boost::asio::error::operation_not_supported);
            });
    }

    void Socks5Client::auth_username_password() {
        // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD
        if (username_.size() > 255 || password_.size() > 255) {
            return fail(boost::asio::error::invalid_argument);
        }

        buf_.clear();
        buf_.push_back(kAuthVer);
        buf_.push_back(static_cast<std::uint8_t>(username_.size()));
        buf_.insert(buf_.end(), username_.begin(), username_.end());
        buf_.push_back(static_cast<std::uint8_t>(password_.size()));
        buf_.insert(buf_.end(), password_.begin(), password_.end());

        auto self = shared_from_this();
        boost::asio::async_write(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);

                buf_.assign(2, 0);
                boost::asio::async_read(sock_, boost::asio::buffer(buf_),
                    [this, self](const boost::system::error_code& ec2, std::size_t) {
                        if (ec2) return fail(ec2);
                        if (buf_[0] != kAuthVer) return fail(boost::asio::error::operation_not_supported);
                        if (buf_[1] != 0x00) return fail(boost::asio::error::access_denied);
                        send_connect_request();
                    });
            });
    }

    void Socks5Client::send_connect_request() {
        // VER CMD RSV ATYP DST.ADDR DST.PORT
        // ВАЖНО: отправляем домен как DOMAIN (не резолвим локально)
        if (dst_host_.size() > 255) {
            return fail(boost::asio::error::invalid_argument);
        }

        buf_.clear();
        buf_.push_back(kVer);
        buf_.push_back(kCmdConnect);
        buf_.push_back(0x00); // RSV
        buf_.push_back(kAtypDomain);
        buf_.push_back(static_cast<std::uint8_t>(dst_host_.size()));
        buf_.insert(buf_.end(), dst_host_.begin(), dst_host_.end());

        buf_.push_back(static_cast<std::uint8_t>((dst_port_ >> 8) & 0xFF));
        buf_.push_back(static_cast<std::uint8_t>(dst_port_ & 0xFF));

        auto self = shared_from_this();
        boost::asio::async_write(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                read_connect_reply_header();
            });
    }

    void Socks5Client::read_connect_reply_header() {
        // VER REP RSV ATYP
        auto self = shared_from_this();
        buf_.assign(4, 0);

        boost::asio::async_read(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                if (buf_[0] != kVer) return fail(boost::asio::error::operation_not_supported);
                const std::uint8_t rep = buf_[1];
                const std::uint8_t atyp = buf_[3];
                if (rep != 0x00) return fail(boost::asio::error::connection_refused);
                read_connect_reply_rest(atyp);
            });
    }

    void Socks5Client::read_connect_reply_rest(std::uint8_t atyp) {
        // BND.ADDR + BND.PORT (нам не важно содержимое, но надо считать)
        std::size_t addr_len = 0;
        if (atyp == kAtypIPv4) addr_len = 4;
        else if (atyp == kAtypIPv6) addr_len = 16;
        else if (atyp == kAtypDomain) {
            auto self = shared_from_this();
            buf_.assign(1, 0);
            return boost::asio::async_read(sock_, boost::asio::buffer(buf_),
                [this, self](const boost::system::error_code& ec, std::size_t) {
                    if (ec) return fail(ec);
                    const std::size_t n = buf_[0];
                    buf_.assign(n + 2, 0);
                    boost::asio::async_read(sock_, boost::asio::buffer(buf_),
                        [this, self](const boost::system::error_code& ec2, std::size_t) {
                            if (ec2) return fail(ec2);
                            done_({});
                        });
                });
        }
        else {
            return fail(boost::asio::error::operation_not_supported);
        }

        auto self = shared_from_this();
        buf_.assign(addr_len + 2, 0);
        boost::asio::async_read(sock_, boost::asio::buffer(buf_),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) return fail(ec);
                done_({});
            });
    }

    void Socks5Client::fail(const boost::system::error_code& ec) {
        if (done_) done_(ec);
    }

} // namespace proxycore::net