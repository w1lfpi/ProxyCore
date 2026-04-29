#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace proxycore::tun {

    struct TcpFlowKey {
        std::uint32_t src_ip = 0;
        std::uint32_t dst_ip = 0;
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;

        bool operator==(const TcpFlowKey& other) const noexcept {
            return src_ip == other.src_ip &&
                dst_ip == other.dst_ip &&
                src_port == other.src_port &&
                dst_port == other.dst_port;
        }
    };

    struct TcpFlowKeyHash {
        std::size_t operator()(const TcpFlowKey& k) const noexcept;
    };

    struct ParsedTcpPacket {
        TcpFlowKey key{};
        std::uint8_t tcp_flags = 0;
        std::uint32_t seq = 0;
        std::uint32_t ack = 0;
        std::size_t payload_size = 0;
    };

    class TcpFlowTracker {
    public:
        bool inspect_packet(const std::vector<std::uint8_t>& packet);

    private:
        bool parse_ipv4_tcp(const std::vector<std::uint8_t>& packet, ParsedTcpPacket& out) const;
        static std::string ipv4_to_string(std::uint32_t ip_host_order);

    private:
        std::unordered_map<TcpFlowKey, std::size_t, TcpFlowKeyHash> flows_;
    };

} // namespace proxycore::tun