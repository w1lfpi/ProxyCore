#include "pal/pal_factory.hpp"
#include <spdlog/spdlog.h>

#include "proxycore/core/tun/dns_proxy.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

    std::uint16_t be16(const std::uint8_t* p) {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    }

    std::string ipv4_to_string(const std::uint8_t* p) {
        return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
            std::to_string(p[2]) + "." + std::to_string(p[3]);
    }

    std::string ipv6_to_string(const std::uint8_t* p) {
        auto hex4 = [](std::uint16_t v) {
            const char* hex = "0123456789abcdef";
            std::string s(4, '0');
            s[0] = hex[(v >> 12) & 0xF];
            s[1] = hex[(v >> 8) & 0xF];
            s[2] = hex[(v >> 4) & 0xF];
            s[3] = hex[v & 0xF];
            return s;
            };

        std::string out;
        for (int i = 0; i < 8; ++i) {
            std::uint16_t w = static_cast<std::uint16_t>((p[i * 2] << 8) | p[i * 2 + 1]);
            out += hex4(w);
            if (i != 7) out += ":";
        }
        return out;
    }

    void parse_and_log_packet(const std::uint8_t* data, std::size_t len) {
        if (len < 1) return;

        const std::uint8_t ver = (data[0] >> 4) & 0xF;

        if (ver == 4) {
            if (len < 20) return;

            const std::uint8_t ihl = (data[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl) return;

            const std::uint8_t proto = data[9];
            const std::string src = ipv4_to_string(&data[12]);
            const std::string dst = ipv4_to_string(&data[16]);

            if (proto == 6) {
                if (len < ihl + 20) { spdlog::info("[tun] IPv4 TCP {} -> {} (short)", src, dst); return; }
                const std::uint16_t sport = be16(&data[ihl + 0]);
                const std::uint16_t dport = be16(&data[ihl + 2]);
                spdlog::info("[tun] IPv4 TCP {}:{} -> {}:{}", src, sport, dst, dport);
            }
            else if (proto == 17) {
                if (len < ihl + 8) { spdlog::info("[tun] IPv4 UDP {} -> {} (short)", src, dst); return; }
                const std::uint16_t sport = be16(&data[ihl + 0]);
                const std::uint16_t dport = be16(&data[ihl + 2]);
                spdlog::info("[tun] IPv4 UDP {}:{} -> {}:{}", src, sport, dst, dport);
            }
            else if (proto == 1) {
                spdlog::info("[tun] IPv4 ICMP {} -> {}", src, dst);
            }
            else {
                spdlog::info("[tun] IPv4 proto={} {} -> {}", (int)proto, src, dst);
            }
            return;
        }

        if (ver == 6) {
            if (len < 40) return;

            const std::uint8_t next = data[6];
            const std::string src = ipv6_to_string(&data[8]);
            const std::string dst = ipv6_to_string(&data[24]);

            if (next == 6) spdlog::info("[tun] IPv6 TCP {} -> {}", src, dst);
            else if (next == 17) spdlog::info("[tun] IPv6 UDP {} -> {}", src, dst);
            else if (next == 58) spdlog::info("[tun] IPv6 ICMPv6 {} -> {}", src, dst);
            else spdlog::info("[tun] IPv6 next={} {} -> {}", (int)next, src, dst);
            return;
        }

        spdlog::info("[tun] unknown packet (first_byte=0x{:02x}, len={})", data[0], (int)len);
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

    bool parse_ipv4_basic(const std::uint8_t* pkt, std::size_t len,
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

    bool is_same_ipv4(const std::uint8_t a[4], const std::uint8_t b[4]) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
    }

    bool make_icmpv4_echo_reply(const std::uint8_t* in_pkt, std::size_t in_len,
        const std::uint8_t my_ip[4],
        proxycore::pal::ITunDevice::Packet& out_pkt) {
        std::size_t ihl = 0;
        std::uint8_t proto = 0;
        std::uint8_t src[4]{}, dst[4]{};

        if (!parse_ipv4_basic(in_pkt, in_len, ihl, proto, src, dst)) return false;
        if (proto != 1) return false; // ICMP
        if (!is_same_ipv4(dst, my_ip)) return false;

        if (in_len < ihl + 8) return false;
        const std::uint8_t icmp_type = in_pkt[ihl + 0];
        const std::uint8_t icmp_code = in_pkt[ihl + 1];
        if (icmp_type != 8 || icmp_code != 0) return false; // Echo Request

        out_pkt.assign(in_pkt, in_pkt + in_len);

        // swap src/dst
        std::memcpy(out_pkt.data() + 12, dst, 4);
        std::memcpy(out_pkt.data() + 16, src, 4);

        // ICMP type=0 reply
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

    // маленький фильтр: логировать UDP/53 всегда (чтобы видеть nslookup даже после "первых 50")
    bool is_ipv4_udp_to_port(const std::uint8_t* data, std::size_t len, std::uint16_t dport) {
        if (len < 20) return false;
        const std::uint8_t ver = (data[0] >> 4) & 0xF;
        if (ver != 4) return false;

        const std::size_t ihl = static_cast<std::size_t>(data[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8) return false;

        const std::uint8_t proto = data[9];
        if (proto != 17) return false; // UDP

        const std::uint16_t dp = be16(&data[ihl + 2]);
        return dp == dport;
    }

#if defined(_WIN32)
    bool run_netsh_set_ipv4(const std::string& if_name, const std::string& ip, const std::string& mask) {
        std::string cmd = "netsh interface ip set address name=\"" + if_name + "\" static " + ip + " " + mask;

        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        std::string mutable_cmd = cmd;

        BOOL ok = CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

        if (!ok) {
            spdlog::error("[tun_probe] netsh CreateProcess failed: {}", (int)GetLastError());
            return false;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        if (exit_code != 0) {
            spdlog::error("[tun_probe] netsh exit code={}", (int)exit_code);
            return false;
        }
        return true;
    }
#endif

} // namespace

int main() {
    auto tun = proxycore::pal::PalFactory::create_tun();
    if (!tun) {
        spdlog::error("[tun_probe] TUN not supported on this platform (factory returned null)");
        return 1;
    }

    proxycore::pal::TunConfig cfg;
    cfg.name = "proxycore-tun-probe";
    cfg.ipv4_addr = "10.7.0.1";
    cfg.ipv4_prefix = 24;

    const std::uint8_t my_ip[4]{ 10, 7, 0, 1 };

    std::atomic<int> to_log{ 50 };
    std::atomic<std::uint64_t> icmp_replies{ 0 };

    proxycore::core::tun::DnsProxy dns(*tun);
    proxycore::core::tun::DnsProxy::Config dcfg;
    dcfg.upstream_ip = "1.1.1.1";
    dcfg.upstream_port = 53;
    dns.start(dcfg);

    tun->set_read_handler([&](proxycore::pal::ITunDevice::Packet pkt) {
        // 0) DNS обработчик — ВСЕГДА (не только первые 50!)
        dns.on_tun_packet(pkt.data(), pkt.size());

        // 1) лог первых 50 пакетов
        int left = to_log.load();
        if (left > 0 && to_log.compare_exchange_strong(left, left - 1)) {
            parse_and_log_packet(pkt.data(), pkt.size());
        }

        // 2) логировать UDP/53 всегда (удобно для nslookup)
        if (is_ipv4_udp_to_port(pkt.data(), pkt.size(), 53)) {
            spdlog::info("[tun] IPv4 UDP -> dport=53 (DNS packet seen)");
        }

        // 3) ICMP echo reply (если Echo Request реально приходит через TUN)
        proxycore::pal::ITunDevice::Packet reply;
        if (make_icmpv4_echo_reply(pkt.data(), pkt.size(), my_ip, reply)) {
            if (tun->write(std::move(reply))) {
                ++icmp_replies;
            }
        }
        });

    if (!tun->start(cfg)) {
        spdlog::error("[tun_probe] start failed (try running as Administrator)");
        return 1;
    }

#if defined(_WIN32)
    if (!cfg.ipv4_addr.empty() && cfg.ipv4_prefix == 24) {
        if (run_netsh_set_ipv4(cfg.name, cfg.ipv4_addr, "255.255.255.0")) {
            spdlog::info("[tun_probe] ipv4 set via netsh: {}/24", cfg.ipv4_addr);
        }
        else {
            spdlog::warn("[tun_probe] failed to set ipv4 via netsh");
        }
    }
#endif

    spdlog::info("[tun_probe] started. sleeping 60 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(60));

    auto st = tun->stats();
    spdlog::info("[tun_probe] stats: in_pkts={} out_pkts={} in_bytes={} out_bytes={} icmp_replies={}",
        st.packets_in, st.packets_out, st.bytes_in, st.bytes_out,
        (std::uint64_t)icmp_replies.load());

    auto ds = dns.stats();
    spdlog::info("[dns_proxy] stats: queries={} answers={} dropped={}",
        ds.dns_queries, ds.dns_answers, ds.dns_dropped);

    dns.stop();
    tun->stop();
    spdlog::info("[tun_probe] stopped");
    return 0;
}