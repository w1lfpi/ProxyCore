#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace proxycore::core::tun {

    struct IPv4UdpView {
        bool ok = false;

        // IPv4
        std::size_t ip_hlen = 0;           // bytes
        std::uint8_t proto = 0;            // 17 for UDP
        std::uint16_t ip_total_len = 0;    // from header
        std::uint8_t src_ip[4]{};
        std::uint8_t dst_ip[4]{};

        // UDP
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;
        std::uint16_t udp_len = 0;

        // Payload
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
    };

    // Разбор IPv4+UDP (L3 пакет из TUN)
    IPv4UdpView parse_ipv4_udp(const std::uint8_t* pkt, std::size_t len);

    // Сборка IPv4+UDP (ответа) с корректными checksum.
    // src/dst и порты задаёшь явным образом.
    std::vector<std::uint8_t> build_ipv4_udp_packet(
        const std::uint8_t src_ip[4],
        const std::uint8_t dst_ip[4],
        std::uint16_t src_port,
        std::uint16_t dst_port,
        const std::uint8_t* payload,
        std::size_t payload_len);

    // Утилиты
    std::uint16_t checksum16(const std::uint8_t* data, std::size_t len);

} // namespace proxycore::core::tun