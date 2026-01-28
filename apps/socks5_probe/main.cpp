#include <boost/asio.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

static std::string rep_to_string(std::uint8_t rep) {
    switch (rep) {
    case 0x00: return "0x00 succeeded";
    case 0x01: return "0x01 general SOCKS server failure";
    case 0x02: return "0x02 connection not allowed by ruleset";
    case 0x03: return "0x03 network unreachable";
    case 0x04: return "0x04 host unreachable";
    case 0x05: return "0x05 connection refused";
    case 0x06: return "0x06 TTL expired";
    case 0x07: return "0x07 command not supported";
    case 0x08: return "0x08 address type not supported";
    default:   return "unknown REP";
    }
}

static std::string method_to_string(std::uint8_t m) {
    switch (m) {
    case 0x00: return "0x00 NO AUTH";
    case 0x02: return "0x02 USERPASS";
    case 0xFF: return "0xFF NO ACCEPTABLE METHODS";
    default:   return "unknown METHOD";
    }
}

static bool read_exact(boost::asio::ip::tcp::socket& sock, void* data, std::size_t n) {
    boost::system::error_code ec;
    boost::asio::read(sock, boost::asio::buffer(data, n), ec);
    return !ec;
}

static bool write_all(boost::asio::ip::tcp::socket& sock, const void* data, std::size_t n) {
    boost::system::error_code ec;
    boost::asio::write(sock, boost::asio::buffer(data, n), ec);
    return !ec;
}

static bool socks5_greeting(boost::asio::ip::tcp::socket& sock, bool offer_userpass, std::uint8_t& chosen_method) {
    // RFC 1928: VER, NMETHODS, METHODS...
    // VER=0x05
    std::vector<std::uint8_t> req;
    req.push_back(0x05);
    if (offer_userpass) {
        req.push_back(2);
        req.push_back(0x00); // no-auth
        req.push_back(0x02); // user/pass
    }
    else {
        req.push_back(1);
        req.push_back(0x00); // no-auth
    }

    if (!write_all(sock, req.data(), req.size())) return false;

    std::uint8_t resp[2]{};
    if (!read_exact(sock, resp, 2)) return false;

    if (resp[0] != 0x05) return false;
    chosen_method = resp[1];
    return true;
}

static bool socks5_userpass_auth(boost::asio::ip::tcp::socket& sock,
    const std::string& user,
    const std::string& pass,
    std::uint8_t& status) {
    // RFC 1929: VER=0x01, ULEN, UNAME, PLEN, PASSWD
    if (user.size() > 255 || pass.size() > 255) return false;

    std::vector<std::uint8_t> req;
    req.push_back(0x01);
    req.push_back(static_cast<std::uint8_t>(user.size()));
    req.insert(req.end(), user.begin(), user.end());
    req.push_back(static_cast<std::uint8_t>(pass.size()));
    req.insert(req.end(), pass.begin(), pass.end());

    if (!write_all(sock, req.data(), req.size())) return false;

    std::uint8_t resp[2]{};
    if (!read_exact(sock, resp, 2)) return false;

    if (resp[0] != 0x01) return false;
    status = resp[1]; // 0x00 success
    return true;
}

static bool socks5_connect_domain(boost::asio::ip::tcp::socket& sock,
    const std::string& host,
    std::uint16_t port,
    std::uint8_t& rep_out) {
    // RFC 1928 CONNECT: VER CMD RSV ATYP DST.ADDR DST.PORT
    // ATYP=0x03 DOMAIN: 1 byte len + host bytes
    if (host.size() > 255) return false;

    std::vector<std::uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01); // CONNECT
    req.push_back(0x00); // RSV
    req.push_back(0x03); // DOMAIN
    req.push_back(static_cast<std::uint8_t>(host.size()));
    req.insert(req.end(), host.begin(), host.end());
    req.push_back(static_cast<std::uint8_t>((port >> 8) & 0xFF));
    req.push_back(static_cast<std::uint8_t>(port & 0xFF));

    if (!write_all(sock, req.data(), req.size())) return false;

    // Reply: VER REP RSV ATYP ...
    std::uint8_t hdr[4]{};
    if (!read_exact(sock, hdr, 4)) return false;

    if (hdr[0] != 0x05) return false;
    rep_out = hdr[1];

    const std::uint8_t atyp = hdr[3];

    // consume BND.ADDR + BND.PORT
    if (atyp == 0x01) { // IPv4
        std::uint8_t rest[4 + 2]{};
        if (!read_exact(sock, rest, sizeof(rest))) return false;
    }
    else if (atyp == 0x04) { // IPv6
        std::vector<std::uint8_t> rest(16 + 2);
        if (!read_exact(sock, rest.data(), rest.size())) return false;
    }
    else if (atyp == 0x03) { // DOMAIN
        std::uint8_t len{};
        if (!read_exact(sock, &len, 1)) return false;
        std::vector<std::uint8_t> rest(static_cast<std::size_t>(len) + 2);
        if (!read_exact(sock, rest.data(), rest.size())) return false;
    }
    else {
        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    // Usage:
    // socks5_probe <up_host> <up_port> [user] [pass] [dst_host] [dst_port]
    if (argc < 3) {
        std::cout
            << "Usage:\n"
            << "  socks5_probe <up_host> <up_port> [user] [pass] [dst_host] [dst_port]\n\n"
            << "Examples:\n"
            << "  socks5_probe 1.2.3.4 1080\n"
            << "  socks5_probe 1.2.3.4 1080 user pass\n"
            << "  socks5_probe 1.2.3.4 1080 user pass www.youtube.com 443\n";
        return 2;
    }

    const std::string up_host = argv[1];
    const std::uint16_t up_port = static_cast<std::uint16_t>(std::stoi(argv[2]));

    std::string user;
    std::string pass;
    if (argc >= 5) {
        user = argv[3];
        pass = argv[4];
    }

    std::string dst_host = "example.com";
    std::uint16_t dst_port = 443;
    if (argc >= 7) {
        dst_host = argv[5];
        dst_port = static_cast<std::uint16_t>(std::stoi(argv[6]));
    }

    try {
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::resolver resolver(ioc);
        boost::asio::ip::tcp::socket sock(ioc);

        std::cout << "[probe] connecting to " << up_host << ":" << up_port << "...\n";

        boost::system::error_code ec;
        auto results = resolver.resolve(up_host, std::to_string(up_port), ec);
        if (ec) {
            std::cout << "[probe] resolve failed: " << ec.message() << "\n";
            return 1;
        }

        boost::asio::connect(sock, results, ec);
        if (ec) {
            std::cout << "[probe] connect failed: " << ec.message() << "\n";
            return 1;
        }

        const bool offer_userpass = (!user.empty() || !pass.empty());
        std::uint8_t method = 0xFF;

        if (!socks5_greeting(sock, offer_userpass, method)) {
            std::cout << "[probe] greeting failed (not SOCKS5 or connection closed)\n";
            return 1;
        }

        std::cout << "[probe] server method: " << method_to_string(method) << "\n";

        if (method == 0xFF) {
            std::cout << "[probe] server refused all methods\n";
            return 1;
        }

        if (method == 0x02) {
            if (user.empty() && pass.empty()) {
                std::cout << "[probe] server requires USERPASS, but no credentials provided\n";
                return 1;
            }
            std::uint8_t status = 0xFF;
            if (!socks5_userpass_auth(sock, user, pass, status)) {
                std::cout << "[probe] USERPASS auth protocol failed (connection closed?)\n";
                return 1;
            }
            std::cout << "[probe] USERPASS status: " << (status == 0x00 ? "OK" : "FAIL") << " (0x"
                << std::hex << (int)status << std::dec << ")\n";
            if (status != 0x00) return 1;
        }

        std::cout << "[probe] CONNECT " << dst_host << ":" << dst_port << "...\n";
        std::uint8_t rep = 0xFF;
        if (!socks5_connect_domain(sock, dst_host, dst_port, rep)) {
            std::cout << "[probe] CONNECT failed (protocol/connection)\n";
            return 1;
        }

        std::cout << "[probe] CONNECT REP: " << rep_to_string(rep) << " (0x"
            << std::hex << (int)rep << std::dec << ")\n";

        if (rep != 0x00) return 1;

        std::cout << "[probe] OK: upstream tunnel established\n";
        return 0;
    }
    catch (const std::exception& ex) {
        std::cout << "[probe] exception: " << ex.what() << "\n";
        return 1;
    }
}