#include "proxycore/core/tun/ip_packets.hpp"
#include <cstring>

namespace proxycore::core::tun {

    static std::uint16_t be16(const std::uint8_t* p) {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    }

    static void put_be16(std::uint8_t* p, std::uint16_t v) {
        p[0] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[1] = static_cast<std::uint8_t>(v & 0xFF);
    }

    std::uint16_t checksum16(const std::uint8_t* data, std::size_t len) {
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

    IPv4UdpView parse_ipv4_udp(const std::uint8_t* pkt, std::size_t len) {
        IPv4UdpView v{};

        if (!pkt || len < 20) return v;

        const std::uint8_t ver = (pkt[0] >> 4) & 0xF;
        if (ver != 4) return v;

        const std::size_t ihl = static_cast<std::size_t>(pkt[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return v;

        const std::uint16_t total_len = be16(pkt + 2);
        if (total_len < ihl) return v;
        if (len < total_len) {
            // иногда в TUN может прийти ровно total_len, но len меньше — не обрабатываем
            return v;
        }

        const std::uint8_t proto = pkt[9];
        if (proto != 17) return v; // UDP only

        std::memcpy(v.src_ip, pkt + 12, 4);
        std::memcpy(v.dst_ip, pkt + 16, 4);

        if (total_len < ihl + 8) return v;
        const std::size_t udp_off = ihl;

        v.src_port = be16(pkt + udp_off + 0);
        v.dst_port = be16(pkt + udp_off + 2);
        v.udp_len = be16(pkt + udp_off + 4);

        if (v.udp_len < 8) return v;
        if (udp_off + v.udp_len > total_len) return v;

        v.payload = pkt + udp_off + 8;
        v.payload_len = static_cast<std::size_t>(v.udp_len - 8);

        v.ok = true;
        v.ip_hlen = ihl;
        v.proto = proto;
        v.ip_total_len = total_len;

        return v;
    }

    static std::uint16_t udp_checksum_ipv4(
        const std::uint8_t src_ip[4],
        const std::uint8_t dst_ip[4],
        const std::uint8_t* udp_hdr_and_payload,
        std::size_t udp_len)
    {
        // UDP checksum with IPv4 pseudo-header.
        // pseudo: src(4) dst(4) zero(1) proto(1) udp_len(2)
        std::uint32_t sum = 0;

        auto add16 = [&sum](std::uint16_t x) { sum += x; };

        add16(static_cast<std::uint16_t>((src_ip[0] << 8) | src_ip[1]));
        add16(static_cast<std::uint16_t>((src_ip[2] << 8) | src_ip[3]));
        add16(static_cast<std::uint16_t>((dst_ip[0] << 8) | dst_ip[1]));
        add16(static_cast<std::uint16_t>((dst_ip[2] << 8) | dst_ip[3]));
        add16(static_cast<std::uint16_t>(0x0011)); // zero+proto(17)
        add16(static_cast<std::uint16_t>(udp_len));

        // UDP header + payload
        std::size_t i = 0;
        while (i + 1 < udp_len) {
            add16(static_cast<std::uint16_t>((udp_hdr_and_payload[i] << 8) | udp_hdr_and_payload[i + 1]));
            i += 2;
        }
        if (i < udp_len) {
            add16(static_cast<std::uint16_t>(udp_hdr_and_payload[i] << 8));
        }

        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        std::uint16_t out = static_cast<std::uint16_t>(~sum);

        // RFC: checksum 0 means "not used", but for IPv4 UDP it’s allowed.
        // If computed 0, set to 0xFFFF sometimes, but мы оставим 0 как есть — Windows обычно ок.
        return out;
    }

    std::vector<std::uint8_t> build_ipv4_udp_packet(
        const std::uint8_t src_ip[4],
        const std::uint8_t dst_ip[4],
        std::uint16_t src_port,
        std::uint16_t dst_port,
        const std::uint8_t* payload,
        std::size_t payload_len)
    {
        const std::size_t ip_hlen = 20;
        const std::size_t udp_hlen = 8;
        const std::size_t udp_len = udp_hlen + payload_len;
        const std::size_t total_len = ip_hlen + udp_len;

        std::vector<std::uint8_t> pkt(total_len, 0);

        // IPv4 header
        pkt[0] = 0x45;                 // ver=4, ihl=5
        pkt[1] = 0x00;                 // DSCP/ECN
        put_be16(pkt.data() + 2, static_cast<std::uint16_t>(total_len));
        put_be16(pkt.data() + 4, 0);   // id
        put_be16(pkt.data() + 6, 0);   // flags/frag
        pkt[8] = 64;                   // TTL
        pkt[9] = 17;                   // UDP
        // checksum later
        std::memcpy(pkt.data() + 12, src_ip, 4);
        std::memcpy(pkt.data() + 16, dst_ip, 4);

        // UDP header
        const std::size_t udp_off = ip_hlen;
        put_be16(pkt.data() + udp_off + 0, src_port);
        put_be16(pkt.data() + udp_off + 2, dst_port);
        put_be16(pkt.data() + udp_off + 4, static_cast<std::uint16_t>(udp_len));
        put_be16(pkt.data() + udp_off + 6, 0); // checksum later

        // payload
        if (payload_len && payload) {
            std::memcpy(pkt.data() + udp_off + udp_hlen, payload, payload_len);
        }

        // IPv4 checksum
        pkt[10] = 0; pkt[11] = 0;
        const std::uint16_t ip_sum = checksum16(pkt.data(), ip_hlen);
        put_be16(pkt.data() + 10, ip_sum);

        // UDP checksum
        pkt[udp_off + 6] = 0; pkt[udp_off + 7] = 0;
        const std::uint16_t udp_sum = udp_checksum_ipv4(src_ip, dst_ip, pkt.data() + udp_off, udp_len);
        put_be16(pkt.data() + udp_off + 6, udp_sum);

        return pkt;
    }

} // namespace proxycore::core::tun