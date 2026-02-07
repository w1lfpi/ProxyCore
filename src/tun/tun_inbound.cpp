#include "proxycore/tun/tun_inbound.hpp"
#include <cstring>
#include <spdlog/spdlog.h>

namespace proxycore::tun {

    TunInbound::TunInbound(proxycore::pal::TunDevicePtr tun)
        : tun_(std::move(tun)) {
    }

    TunInbound::~TunInbound() {
        stop();
    }

    bool TunInbound::start(const Config& cfg) {
        if (!tun_) return false;

        cfg_ = cfg;

        // ipv4_addr "10.7.0.1" -> bytes (минимально, без общего парсера)
        // Если захочешь — сделаем нормальный parse IPv4.
        my_ip_[0] = 10; my_ip_[1] = 7; my_ip_[2] = 0; my_ip_[3] = 1;

        proxycore::pal::TunConfig pcfg;
        pcfg.name = cfg_.name;
        pcfg.ipv4_addr = cfg_.ipv4_addr;
        pcfg.ipv4_prefix = cfg_.ipv4_prefix;

        tun_->set_read_handler([this](proxycore::pal::ITunDevice::Packet pkt) {
            this->on_packet(std::move(pkt));
            });

        if (!tun_->start(pcfg)) {
            spdlog::error("[tun_inbound] tun start failed");
            return false;
        }

        running_.store(true);
        spdlog::info("[tun_inbound] started name={} ipv4={}/{}",
            cfg_.name, cfg_.ipv4_addr, (int)cfg_.ipv4_prefix);
        return true;
    }

    void TunInbound::stop() {
        if (!tun_) return;
        if (!running_.exchange(false)) return;

        tun_->stop();
        spdlog::info("[tun_inbound] stopped");
    }

    proxycore::pal::TunStats TunInbound::stats() const {
        if (!tun_) return {};
        return tun_->stats();
    }

    void TunInbound::on_packet(proxycore::pal::ITunDevice::Packet pkt) {
        if (!running_.load()) return;

        // Минимальная логика ядра: отвечаем на ping своего IPv4.
        proxycore::pal::ITunDevice::Packet reply;
        if (make_icmpv4_echo_reply(pkt.data(), pkt.size(), my_ip_, reply)) {
            (void)tun_->write(std::move(reply));
            return;
        }

        // Дальше тут будет:
        // - разбор TCP/UDP (5-tuple)
        // - NAT/session table
        // - форвардинг через socks5_client/tcp_relay
    }

    std::uint16_t TunInbound::checksum16(const std::uint8_t* data, std::size_t len) {
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

    bool TunInbound::parse_ipv4(const std::uint8_t* pkt, std::size_t len,
        std::size_t& ihl_bytes,
        std::uint8_t& proto,
        std::uint8_t src[4],
        std::uint8_t dst[4]) {
        if (len < 20) return false;
        const std::uint8_t ver = (pkt[0] >> 4) & 0xF;
        if (ver != 4) return false;

        ihl_bytes = static_cast<std::size_t>(pkt[0] & 0x0F) * 4;
        if (ihl_bytes < 20 || len < ihl_bytes) return false;

        proto = pkt[9];
        std::memcpy(src, pkt + 12, 4);
        std::memcpy(dst, pkt + 16, 4);
        return true;
    }

    bool TunInbound::is_same_ipv4(const std::uint8_t a[4], const std::uint8_t b[4]) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
    }

    bool TunInbound::make_icmpv4_echo_reply(const std::uint8_t* in_pkt, std::size_t in_len,
        const std::uint8_t my_ip[4],
        proxycore::pal::ITunDevice::Packet& out_pkt) {
        std::size_t ihl = 0;
        std::uint8_t proto = 0;
        std::uint8_t src[4]{}, dst[4]{};

        if (!parse_ipv4(in_pkt, in_len, ihl, proto, src, dst)) return false;
        if (proto != 1) return false; // ICMP
        if (!is_same_ipv4(dst, my_ip)) return false;

        if (in_len < ihl + 8) return false;
        const std::uint8_t icmp_type = in_pkt[ihl + 0];
        const std::uint8_t icmp_code = in_pkt[ihl + 1];
        if (icmp_type != 8 || icmp_code != 0) return false;

        out_pkt.assign(in_pkt, in_pkt + in_len);

        // swap src/dst
        std::memcpy(out_pkt.data() + 12, dst, 4);
        std::memcpy(out_pkt.data() + 16, src, 4);

        // type=0 reply
        out_pkt[ihl + 0] = 0;
        out_pkt[ihl + 1] = 0;

        // ICMP checksum
        out_pkt[ihl + 2] = 0;
        out_pkt[ihl + 3] = 0;
        const std::uint16_t icmp_sum = checksum16(out_pkt.data() + ihl, in_len - ihl);
        out_pkt[ihl + 2] = static_cast<std::uint8_t>((icmp_sum >> 8) & 0xFF);
        out_pkt[ihl + 3] = static_cast<std::uint8_t>(icmp_sum & 0xFF);

        // IPv4 header checksum
        out_pkt[10] = 0;
        out_pkt[11] = 0;
        const std::uint16_t ip_sum = checksum16(out_pkt.data(), ihl);
        out_pkt[10] = static_cast<std::uint8_t>((ip_sum >> 8) & 0xFF);
        out_pkt[11] = static_cast<std::uint8_t>(ip_sum & 0xFF);

        return true;
    }

} // namespace proxycore::tun