#include "pal/pal_factory.hpp"
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static std::uint16_t be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

static std::string ipv4_to_string(const std::uint8_t* p) {
    return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
        std::to_string(p[2]) + "." + std::to_string(p[3]);
}

static std::string ipv6_to_string(const std::uint8_t* p) {
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

static void parse_and_log_packet(const std::uint8_t* data, std::size_t len) {
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

        if (next == 6) {
            spdlog::info("[tun] IPv6 TCP {} -> {}", src, dst);
        }
        else if (next == 17) {
            spdlog::info("[tun] IPv6 UDP {} -> {}", src, dst);
        }
        else if (next == 58) {
            spdlog::info("[tun] IPv6 ICMPv6 {} -> {}", src, dst);
        }
        else {
            spdlog::info("[tun] IPv6 next={} {} -> {}", (int)next, src, dst);
        }
        return;
    }

    spdlog::info("[tun] unknown packet (first_byte=0x{:02x}, len={})", data[0], (int)len);
}

#if defined(_WIN32)
static bool run_netsh_set_ipv4(const std::string& if_name, const std::string& ip, const std::string& mask) {
    // netsh interface ip set address name="IF" static IP MASK
    std::string cmd = "netsh interface ip set address name=\"" + if_name + "\" static " + ip + " " + mask;

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // CreateProcess требует mutable buffer
    std::string mutable_cmd = cmd;

    BOOL ok = CreateProcessA(
        nullptr,
        mutable_cmd.data(),
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si, &pi
    );

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

    std::atomic<int> to_log{ 50 };

    tun->set_read_handler([&](proxycore::pal::ITunDevice::Packet pkt) {
        int left = to_log.load();
        if (left <= 0) return;
        if (to_log.compare_exchange_strong(left, left - 1)) {
            parse_and_log_packet(pkt.data(), pkt.size());
        }
        });

    if (!tun->start(cfg)) {
        spdlog::error("[tun_probe] start failed (try running as Administrator)");
        return 1;
    }

#if defined(_WIN32)
    // Назначаем IPv4 через netsh (требует админ права).
    // prefix=24 -> 255.255.255.0
    if (!cfg.ipv4_addr.empty() && cfg.ipv4_prefix == 24) {
        if (run_netsh_set_ipv4(cfg.name, cfg.ipv4_addr, "255.255.255.0")) {
            spdlog::info("[tun_probe] ipv4 set via netsh: {}/24", cfg.ipv4_addr);
        }
        else {
            spdlog::warn("[tun_probe] failed to set ipv4 via netsh");
        }
    }
#endif

    spdlog::info("[tun_probe] started. logging first 50 packets. sleeping 5 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(60));

    auto st = tun->stats();
    spdlog::info("[tun_probe] stats: in_pkts={} out_pkts={} in_bytes={} out_bytes={}",
        st.packets_in, st.packets_out, st.bytes_in, st.bytes_out);

    tun->stop();
    spdlog::info("[tun_probe] stopped");
    return 0;
}