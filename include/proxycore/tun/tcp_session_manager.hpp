#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace proxycore::tun {

    struct TcpSessionKey {
        std::uint32_t src_ip = 0;
        std::uint32_t dst_ip = 0;
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;

        bool operator==(const TcpSessionKey& other) const noexcept {
            return src_ip == other.src_ip &&
                dst_ip == other.dst_ip &&
                src_port == other.src_port &&
                dst_port == other.dst_port;
        }
    };

    struct TcpSessionKeyHash {
        std::size_t operator()(const TcpSessionKey& k) const noexcept;
    };

    enum class TcpSessionState {
        SynSeen,
        EstablishedCandidate,
        Closed
    };

    struct TcpSessionInfo {
        TcpSessionState state = TcpSessionState::SynSeen;
        std::uint32_t initial_seq = 0;
        std::uint32_t last_ack = 0;
        std::size_t syn_seen_count = 0;
        std::size_t packet_count = 0;
    };

    class TcpSessionManager {
    public:
        bool handle_packet(const std::vector<std::uint8_t>& packet);
        std::size_t session_count() const;

    private:
        struct ParsedTcpPacket {
            TcpSessionKey key{};
            std::uint8_t flags = 0;
            std::uint32_t seq = 0;
            std::uint32_t ack = 0;
            std::size_t payload_size = 0;
        };

        bool parse_ipv4_tcp(const std::vector<std::uint8_t>& packet, ParsedTcpPacket& out) const;
        static std::string ipv4_to_string(std::uint32_t ip_be);
        static std::string state_to_string(TcpSessionState state);

    private:
        mutable std::mutex mu_;
        std::unordered_map<TcpSessionKey, TcpSessionInfo, TcpSessionKeyHash> sessions_;
    };

} // namespace proxycore::tun