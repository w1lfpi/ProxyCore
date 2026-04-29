#pragma once

#include "proxycore/pal/tun.hpp"
#include "proxycore/core/tun/tcp_flow_tracker.hpp"
#include "proxycore/tun/tcp_session_manager.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace proxycore::tun {

    class TunInbound {
    public:
        struct Config {
            std::string name = "proxycore-tun";
            std::string ipv4_addr = "10.7.0.1";
            std::uint8_t ipv4_prefix = 24;
        };

        explicit TunInbound(proxycore::pal::TunDevicePtr tun);
        ~TunInbound();

        bool start(const Config& cfg);
        void stop();

        proxycore::pal::TunStats stats() const;

    private:
        static std::uint16_t checksum16(const std::uint8_t* data, std::size_t len);

        static bool parse_ipv4(
            const std::uint8_t* pkt,
            std::size_t len,
            std::size_t& ihl_bytes,
            std::uint8_t& proto,
            std::uint8_t src[4],
            std::uint8_t dst[4]
        );

        static bool is_same_ipv4(const std::uint8_t a[4], const std::uint8_t b[4]);

        static bool make_icmpv4_echo_reply(
            const std::uint8_t* in_pkt,
            std::size_t in_len,
            const std::uint8_t my_ip[4],
            proxycore::pal::ITunDevice::Packet& out_pkt
        );

        void on_packet(proxycore::pal::ITunDevice::Packet pkt);

    private:
        proxycore::pal::TunDevicePtr tun_;
        Config cfg_{};
        std::atomic<bool> running_{ false };

        std::uint8_t my_ip_[4]{ 10, 7, 0, 1 };
        TcpFlowTracker tcp_tracker_;
        TcpSessionManager tcp_session_manager_;
    };

} // namespace proxycore::tun