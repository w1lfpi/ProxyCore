#include "proxycore/core/tun/tcp_flow_tracker.hpp"

#include <sstream>

#include <spdlog/spdlog.h>

namespace proxycore::tun {

    std::size_t TcpFlowKeyHash::operator()(const TcpFlowKey& k) const noexcept {
        std::size_t h = 0;
        h ^= static_cast<std::size_t>(k.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= static_cast<std::size_t>(k.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= static_cast<std::size_t>(k.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= static_cast<std::size_t>(k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    static std::uint16_t read_be16(const std::uint8_t* p) {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(p[0]) << 8) |
            static_cast<std::uint16_t>(p[1])
            );
    }

    static std::uint32_t read_be32(const std::uint8_t* p) {
        return (static_cast<std::uint32_t>(p[0]) << 24) |
            (static_cast<std::uint32_t>(p[1]) << 16) |
            (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
    }

    bool TcpFlowTracker::inspect_packet(const std::vector<std::uint8_t>& packet) {
        ParsedTcpPacket parsed{};
        if (!parse_ipv4_tcp(packet, parsed)) {
            return false;
        }

        const auto [it, inserted] = flows_.emplace(parsed.key, 1);
        if (!inserted) {
            ++(it->second);
        }

        std::ostringstream flags;
        if (parsed.tcp_flags & 0x02) {
            flags << "SYN ";
        }
        if (parsed.tcp_flags & 0x10) {
            flags << "ACK ";
        }
        if (parsed.tcp_flags & 0x01) {
            flags << "FIN ";
        }
        if (parsed.tcp_flags & 0x04) {
            flags << "RST ";
        }
        if (parsed.tcp_flags & 0x08) {
            flags << "PSH ";
        }

        spdlog::info(
            "[tun][tcp] {}:{} -> {}:{} flags='{}' seq={} ack={} payload={} packets_seen={}",
            ipv4_to_string(parsed.key.src_ip),
            parsed.key.src_port,
            ipv4_to_string(parsed.key.dst_ip),
            parsed.key.dst_port,
            flags.str(),
            parsed.seq,
            parsed.ack,
            parsed.payload_size,
            it->second
        );

        return true;
    }

    bool TcpFlowTracker::parse_ipv4_tcp(const std::vector<std::uint8_t>& packet, ParsedTcpPacket& out) const {
        if (packet.size() < 20) {
            return false;
        }

        const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
        if (version != 4) {
            return false;
        }

        const std::uint8_t ihl_words = static_cast<std::uint8_t>(packet[0] & 0x0F);
        const std::size_t ip_header_len = static_cast<std::size_t>(ihl_words) * 4;
        if (ihl_words < 5 || packet.size() < ip_header_len) {
            return false;
        }

        const std::uint8_t protocol = packet[9];
        if (protocol != 6) {
            return false;
        }

        const std::uint16_t total_len = read_be16(packet.data() + 2);
        if (total_len < ip_header_len + 20 || packet.size() < total_len) {
            return false;
        }

        const std::uint8_t* ip_src = packet.data() + 12;
        const std::uint8_t* ip_dst = packet.data() + 16;

        const std::uint8_t* tcp = packet.data() + ip_header_len;
        const std::size_t tcp_len_available = static_cast<std::size_t>(total_len) - ip_header_len;
        if (tcp_len_available < 20) {
            return false;
        }

        const std::uint16_t src_port = read_be16(tcp + 0);
        const std::uint16_t dst_port = read_be16(tcp + 2);
        const std::uint32_t seq = read_be32(tcp + 4);
        const std::uint32_t ack = read_be32(tcp + 8);

        const std::uint8_t tcp_data_offset_words = static_cast<std::uint8_t>(tcp[12] >> 4);
        const std::size_t tcp_header_len = static_cast<std::size_t>(tcp_data_offset_words) * 4;
        if (tcp_data_offset_words < 5 || tcp_len_available < tcp_header_len) {
            return false;
        }

        const std::uint8_t flags = tcp[13];
        const std::size_t payload_size = tcp_len_available - tcp_header_len;

        out.key.src_ip =
            (static_cast<std::uint32_t>(ip_src[0]) << 24) |
            (static_cast<std::uint32_t>(ip_src[1]) << 16) |
            (static_cast<std::uint32_t>(ip_src[2]) << 8) |
            static_cast<std::uint32_t>(ip_src[3]);

        out.key.dst_ip =
            (static_cast<std::uint32_t>(ip_dst[0]) << 24) |
            (static_cast<std::uint32_t>(ip_dst[1]) << 16) |
            (static_cast<std::uint32_t>(ip_dst[2]) << 8) |
            static_cast<std::uint32_t>(ip_dst[3]);

        out.key.src_port = src_port;
        out.key.dst_port = dst_port;
        out.tcp_flags = flags;
        out.seq = seq;
        out.ack = ack;
        out.payload_size = payload_size;

        return true;
    }

    std::string TcpFlowTracker::ipv4_to_string(std::uint32_t ip_host_order) {
        std::ostringstream oss;
        oss << ((ip_host_order >> 24) & 0xFF) << '.'
            << ((ip_host_order >> 16) & 0xFF) << '.'
            << ((ip_host_order >> 8) & 0xFF) << '.'
            << (ip_host_order & 0xFF);
        return oss.str();
    }

} // namespace proxycore::tun