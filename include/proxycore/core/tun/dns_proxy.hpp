#pragma once
#include <proxycore/pal/tun.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace proxycore::core::tun {

    class DnsProxy {
    public:
        struct Config {
            std::string my_ip = "10.7.0.1";
            std::string upstream_ip = "1.1.1.1";
            std::uint16_t upstream_port = 53;
            int timeout_ms = 2000;
        };

        struct Stats {
            std::uint64_t dns_queries = 0;
            std::uint64_t dns_answers = 0;
            std::uint64_t dns_dropped = 0;
        };

        explicit DnsProxy(proxycore::pal::ITunDevice& tun);

        bool start(const Config& cfg);
        void stop();

        void on_tun_packet(const std::uint8_t* data, std::size_t len);

        Stats stats() const;

    private:
        proxycore::pal::ITunDevice& tun_;
        Config cfg_{};
        std::atomic<bool> running_{ false };

        std::atomic<std::uint64_t> q_{ 0 }, a_{ 0 }, d_{ 0 };

        static std::uint16_t be16(const std::uint8_t* p);
        static void wr16(std::uint8_t* p, std::uint16_t v);
        static std::uint16_t checksum16(const std::uint8_t* data, std::size_t len);

        static bool parse_ipv4_udp(const std::uint8_t* pkt, std::size_t len,
            std::size_t& ihl,
            std::uint8_t src_ip[4],
            std::uint8_t dst_ip[4],
            std::uint16_t& src_port,
            std::uint16_t& dst_port,
            const std::uint8_t*& udp_payload,
            std::size_t& udp_payload_len);

        bool send_upstream_and_reply(const std::uint8_t src_ip[4], std::uint16_t src_port,
            const std::uint8_t* dns_query, std::size_t dns_len);
    };

} // namespace proxycore::core::tun