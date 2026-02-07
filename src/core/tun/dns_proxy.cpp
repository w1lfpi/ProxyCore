#include "proxycore/core/tun/dns_proxy.hpp"

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstring>
#include <vector>

namespace proxycore::core::tun {

    using boost::asio::ip::udp;

    DnsProxy::DnsProxy(proxycore::pal::ITunDevice& tun) : tun_(tun) {}

    bool DnsProxy::start(const Config& cfg) {
        cfg_ = cfg;
        running_.store(true);
        spdlog::info("[dns_proxy] started: my_ip={}, upstream={}:{} timeout_ms={}",
            cfg_.my_ip, cfg_.upstream_ip, cfg_.upstream_port, cfg_.timeout_ms);
        return true;
    }

    void DnsProxy::stop() {
        running_.store(false);
        spdlog::info("[dns_proxy] stopped");
    }

    DnsProxy::Stats DnsProxy::stats() const {
        Stats s{};
        s.dns_queries = q_.load();
        s.dns_answers = a_.load();
        s.dns_dropped = d_.load();
        return s;
    }

    std::uint16_t DnsProxy::be16(const std::uint8_t* p) {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    }
    void DnsProxy::wr16(std::uint8_t* p, std::uint16_t v) {
        p[0] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[1] = static_cast<std::uint8_t>(v & 0xFF);
    }

    std::uint16_t DnsProxy::checksum16(const std::uint8_t* data, std::size_t len) {
        std::uint32_t sum = 0;
        std::size_t i = 0;
        while (i + 1 < len) {
            sum += static_cast<std::uint16_t>((data[i] << 8) | data[i + 1]);
            i += 2;
        }
        if (i < len) sum += static_cast<std::uint16_t>(data[i] << 8);

        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return static_cast<std::uint16_t>(~sum);
    }

    bool DnsProxy::parse_ipv4_udp(const std::uint8_t* pkt, std::size_t len,
        std::size_t& ihl,
        std::uint8_t src_ip[4],
        std::uint8_t dst_ip[4],
        std::uint16_t& src_port,
        std::uint16_t& dst_port,
        const std::uint8_t*& udp_payload,
        std::size_t& udp_payload_len) {
        if (len < 20) return false;
        const std::uint8_t ver = (pkt[0] >> 4) & 0xF;
        if (ver != 4) return false;

        ihl = static_cast<std::size_t>(pkt[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return false;

        const std::uint8_t proto = pkt[9];
        if (proto != 17) return false; // UDP

        std::memcpy(src_ip, pkt + 12, 4);
        std::memcpy(dst_ip, pkt + 16, 4);

        if (len < ihl + 8) return false;
        src_port = be16(pkt + ihl + 0);
        dst_port = be16(pkt + ihl + 2);

        const std::uint16_t udp_len = be16(pkt + ihl + 4);
        if (udp_len < 8) return false;
        if (len < ihl + udp_len) return false;

        udp_payload = pkt + ihl + 8;
        udp_payload_len = static_cast<std::size_t>(udp_len - 8);
        return true;
    }

    static bool ip_str_to_bytes4(const std::string& ip, std::uint8_t out[4]) {
        // простейший парсер "a.b.c.d"
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
        if (a > 255 || b > 255 || c > 255 || d > 255) return false;
        out[0] = (std::uint8_t)a; out[1] = (std::uint8_t)b; out[2] = (std::uint8_t)c; out[3] = (std::uint8_t)d;
        return true;
    }

    bool DnsProxy::send_upstream_and_reply(const std::uint8_t src_ip[4], std::uint16_t src_port,
        const std::uint8_t* dns_query, std::size_t dns_len) {
        try {
            boost::asio::io_context io;

            udp::socket sock(io);
            sock.open(udp::v4());

            udp::endpoint upstream(boost::asio::ip::make_address(cfg_.upstream_ip), cfg_.upstream_port);

            sock.send_to(boost::asio::buffer(dns_query, dns_len), upstream);

            std::array<std::uint8_t, 2048> resp{};
            udp::endpoint from;

            bool got = false;
            std::size_t got_len = 0;

            boost::asio::steady_timer timer(io);
            timer.expires_after(std::chrono::milliseconds(cfg_.timeout_ms));
            timer.async_wait([&](const boost::system::error_code& ec) {
                if (!ec && !got) {
                    boost::system::error_code ignored;
                    sock.cancel(ignored);
                }
                });

            sock.async_receive_from(boost::asio::buffer(resp), from,
                [&](const boost::system::error_code& ec, std::size_t n) {
                    if (!ec) { got = true; got_len = n; }
                    timer.cancel();
                });

            io.run();

            if (!got || got_len < 12) return false;

            // Собираем IPv4+UDP ответ обратно в TUN (UDP checksum = 0, это допустимо для IPv4)
            std::uint8_t my_ip[4]{};
            if (!ip_str_to_bytes4(cfg_.my_ip, my_ip)) return false;

            const std::size_t ip_hl = 20;
            const std::size_t udp_hl = 8;
            const std::size_t total_len = ip_hl + udp_hl + got_len;

            proxycore::pal::ITunDevice::Packet out(total_len);

            // IPv4 header
            out[0] = 0x45;                 // ver=4, ihl=5
            out[1] = 0x00;                 // DSCP/ECN
            wr16(out.data() + 2, (std::uint16_t)total_len);
            wr16(out.data() + 4, 0x0000);  // id
            wr16(out.data() + 6, 0x0000);  // flags/frag
            out[8] = 64;                   // TTL
            out[9] = 17;                   // UDP
            out[10] = 0; out[11] = 0;      // checksum (потом)
            std::memcpy(out.data() + 12, my_ip, 4);     // src = my_ip
            std::memcpy(out.data() + 16, src_ip, 4);    // dst = original src

            // IPv4 checksum
            const std::uint16_t ip_sum = checksum16(out.data(), ip_hl);
            wr16(out.data() + 10, ip_sum);

            // UDP header
            const std::size_t u = ip_hl;
            wr16(out.data() + u + 0, 53);               // src port
            wr16(out.data() + u + 2, src_port);         // dst port (client port)
            wr16(out.data() + u + 4, (std::uint16_t)(udp_hl + got_len));
            wr16(out.data() + u + 6, 0);                // checksum=0 (IPv4 ok)

            // payload
            std::memcpy(out.data() + u + udp_hl, resp.data(), got_len);

            if (!tun_.write(std::move(out))) return false;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    void DnsProxy::on_tun_packet(const std::uint8_t* data, std::size_t len) {
        if (!running_.load()) return;

        std::size_t ihl = 0;
        std::uint8_t src_ip[4]{}, dst_ip[4]{};
        std::uint16_t sport = 0, dport = 0;
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;

        if (!parse_ipv4_udp(data, len, ihl, src_ip, dst_ip, sport, dport, payload, payload_len)) return;
        if (dport != 53) return;

        std::uint8_t my_ip[4]{};
        if (!ip_str_to_bytes4(cfg_.my_ip, my_ip)) return;

        if (std::memcmp(dst_ip, my_ip, 4) != 0) return; // запрос именно к нашему “локальному DNS”
        if (payload_len < 12) return;

        q_.fetch_add(1);

        if (send_upstream_and_reply(src_ip, sport, payload, payload_len)) {
            a_.fetch_add(1);
        }
        else {
            d_.fetch_add(1);
            spdlog::warn("[dns_proxy] dropped query (timeout/fail)");
        }
    }

} // namespace proxycore::core::tun