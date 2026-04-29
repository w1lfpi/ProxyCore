#include "proxycore/tun/tun_inbound.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

#include <spdlog/spdlog.h>

namespace proxycore::tun {

    TunInbound::TunInbound(proxycore::pal::TunDevicePtr tun)
        : tun_(std::move(tun)) {
    }

    TunInbound::~TunInbound() {
        stop();
    }

    bool TunInbound::start(const Config& cfg) {
        if (!tun_) {
            spdlog::error("[tun_inbound] no tun device");
            return false;
        }

        if (running_.load()) {
            return true;
        }

        cfg_ = cfg;

        {
            unsigned a = 10, b = 7, c = 0, d = 1;
            if (std::sscanf(cfg_.ipv4_addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                my_ip_[0] = static_cast<std::uint8_t>(a);
                my_ip_[1] = static_cast<std::uint8_t>(b);
                my_ip_[2] = static_cast<std::uint8_t>(c);
                my_ip_[3] = static_cast<std::uint8_t>(d);
            }
        }

        proxycore::pal::TunConfig tun_cfg;
        tun_cfg.name = cfg_.name;
        tun_cfg.ipv4_addr = cfg_.ipv4_addr;
        tun_cfg.ipv4_prefix = cfg_.ipv4_prefix;

        tun_->set_read_handler([this](proxycore::pal::ITunDevice::Packet pkt) {
            on_packet(std::move(pkt));
            });

        if (!tun_->start(tun_cfg)) {
            spdlog::error(
                "[tun_inbound] failed to start tun device: {} {}/{}",
                cfg_.name,
                cfg_.ipv4_addr,
                static_cast<int>(cfg_.ipv4_prefix)
            );
            return false;
        }

        running_.store(true);

        spdlog::info(
            "[tun_inbound] started: name={} ipv4={}/{}",
            cfg_.name,
            cfg_.ipv4_addr,
            static_cast<int>(cfg_.ipv4_prefix)
        );

        return true;
    }

    void TunInbound::stop() {
        if (!running_.exchange(false)) {
            return;
        }

        if (tun_) {
            tun_->stop();
        }

        spdlog::info("[tun_inbound] stopped");
    }

    proxycore::pal::TunStats TunInbound::stats() const {
        if (!tun_) {
            return {};
        }
        return tun_->stats();
    }

    std::uint16_t TunInbound::checksum16(const std::uint8_t* data, std::size_t len) {
        std::uint32_t sum = 0;

        while (len >= 2) {
            const std::uint16_t word =
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) |
                    static_cast<std::uint16_t>(data[1]));
            sum += word;
            data += 2;
            len -= 2;
        }

        if (len == 1) {
            sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) << 8);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }

        return static_cast<std::uint16_t>(~sum);
    }

    bool TunInbound::parse_ipv4(
        const std::uint8_t* pkt,
        std::size_t len,
        std::size_t& ihl_bytes,
        std::uint8_t& proto,
        std::uint8_t src[4],
        std::uint8_t dst[4]) {
        if (!pkt || len < 20) {
            return false;
        }

        const std::uint8_t version = static_cast<std::uint8_t>(pkt[0] >> 4);
        const std::uint8_t ihl = static_cast<std::uint8_t>(pkt[0] & 0x0F);

        if (version != 4 || ihl < 5) {
            return false;
        }

        ihl_bytes = static_cast<std::size_t>(ihl) * 4;
        if (len < ihl_bytes) {
            return false;
        }

        proto = pkt[9];

        std::memcpy(src, pkt + 12, 4);
        std::memcpy(dst, pkt + 16, 4);

        return true;
    }

    bool TunInbound::is_same_ipv4(const std::uint8_t a[4], const std::uint8_t b[4]) {
        return std::memcmp(a, b, 4) == 0;
    }

    bool TunInbound::make_icmpv4_echo_reply(
        const std::uint8_t* in_pkt,
        std::size_t in_len,
        const std::uint8_t my_ip[4],
        proxycore::pal::ITunDevice::Packet& out_pkt) {
        if (!in_pkt || in_len < 20) {
            return false;
        }

        std::size_t ihl_bytes = 0;
        std::uint8_t proto = 0;
        std::uint8_t src[4]{};
        std::uint8_t dst[4]{};

        if (!parse_ipv4(in_pkt, in_len, ihl_bytes, proto, src, dst)) {
            return false;
        }

        if (proto != 1) {
            return false;
        }

        if (!is_same_ipv4(dst, my_ip)) {
            return false;
        }

        if (in_len < ihl_bytes + 8) {
            return false;
        }

        const std::uint8_t* icmp = in_pkt + ihl_bytes;
        const std::size_t icmp_len = in_len - ihl_bytes;

        if (icmp[0] != 8 || icmp[1] != 0) {
            return false;
        }

        out_pkt.assign(in_pkt, in_pkt + in_len);

        std::uint8_t* out_ip = out_pkt.data();
        std::uint8_t* out_icmp = out_ip + ihl_bytes;

        std::swap(out_ip[12], out_ip[16]);
        std::swap(out_ip[13], out_ip[17]);
        std::swap(out_ip[14], out_ip[18]);
        std::swap(out_ip[15], out_ip[19]);

        out_ip[10] = 0;
        out_ip[11] = 0;
        const std::uint16_t ip_csum = checksum16(out_ip, ihl_bytes);
        out_ip[10] = static_cast<std::uint8_t>((ip_csum >> 8) & 0xFF);
        out_ip[11] = static_cast<std::uint8_t>(ip_csum & 0xFF);

        out_icmp[0] = 0;
        out_icmp[1] = 0;
        out_icmp[2] = 0;
        out_icmp[3] = 0;

        const std::uint16_t icmp_csum = checksum16(out_icmp, icmp_len);
        out_icmp[2] = static_cast<std::uint8_t>((icmp_csum >> 8) & 0xFF);
        out_icmp[3] = static_cast<std::uint8_t>(icmp_csum & 0xFF);

        return true;
    }

    void TunInbound::on_packet(proxycore::pal::ITunDevice::Packet pkt) {
        if (!running_.load()) {
            return;
        }

        tcp_tracker_.inspect_packet(pkt);
        tcp_session_manager_.handle_packet(pkt);

        proxycore::pal::ITunDevice::Packet reply;
        if (make_icmpv4_echo_reply(pkt.data(), pkt.size(), my_ip_, reply)) {
            if (tun_ && !reply.empty()) {
                tun_->write(std::move(reply));
            }
        }
    }

} // namespace proxycore::tun