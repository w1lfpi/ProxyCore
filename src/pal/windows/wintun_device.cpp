#include "wintun_device.hpp"

#if defined(_WIN32)

#include <Windows.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

namespace proxycore::pal {

    namespace {

        std::wstring utf8_to_wstring(const std::string& s) {
            if (s.empty()) {
                return {};
            }

            const int size_needed = MultiByteToWideChar(
                CP_UTF8,
                0,
                s.c_str(),
                static_cast<int>(s.size()),
                nullptr,
                0
            );

            if (size_needed <= 0) {
                return {};
            }

            std::wstring out;
            out.resize(static_cast<std::size_t>(size_needed));

            const int converted = MultiByteToWideChar(
                CP_UTF8,
                0,
                s.c_str(),
                static_cast<int>(s.size()),
                out.data(),
                size_needed
            );

            if (converted <= 0) {
                return {};
            }

            return out;
        }

        std::string prefix_to_mask(std::uint8_t prefix) {
            if (prefix > 32) {
                prefix = 32;
            }

            std::uint32_t mask = (prefix == 0)
                ? 0u
                : (0xFFFFFFFFu << (32 - prefix));

            std::ostringstream oss;
            oss
                << ((mask >> 24) & 0xFF) << '.'
                << ((mask >> 16) & 0xFF) << '.'
                << ((mask >> 8) & 0xFF) << '.'
                << (mask & 0xFF);

            return oss.str();
        }

        std::string ps_escape_single_quotes(const std::string& s) {
            std::string out;
            out.reserve(s.size());

            for (char c : s) {
                if (c == '\'') {
                    out += "''";
                }
                else {
                    out.push_back(c);
                }
            }

            return out;
        }

        bool run_process_wait(const std::wstring& command_line, DWORD& exit_code) {
            STARTUPINFOW si{};
            si.cb = sizeof(si);

            PROCESS_INFORMATION pi{};

            std::vector<wchar_t> cmd(command_line.begin(), command_line.end());
            cmd.push_back(L'\0');

            const BOOL ok = CreateProcessW(
                nullptr,
                cmd.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &si,
                &pi
            );

            if (!ok) {
                exit_code = static_cast<DWORD>(GetLastError());
                return false;
            }

            WaitForSingleObject(pi.hProcess, INFINITE);

            DWORD code = 1;
            GetExitCodeProcess(pi.hProcess, &code);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            exit_code = code;
            return true;
        }

        bool configure_ipv4_powershell(const std::string& if_alias,
            const std::string& ipv4_addr,
            std::uint8_t ipv4_prefix) {
            if (if_alias.empty() || ipv4_addr.empty() || ipv4_prefix == 0) {
                return true;
            }

            const std::string alias_esc = ps_escape_single_quotes(if_alias);
            const std::string ip_esc = ps_escape_single_quotes(ipv4_addr);

            std::ostringstream script;
            script
                << "Get-NetIPAddress -InterfaceAlias '" << alias_esc
                << "' -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
                << "New-NetIPAddress -InterfaceAlias '" << alias_esc
                << "' -IPAddress '" << ip_esc
                << "' -PrefixLength " << static_cast<int>(ipv4_prefix)
                << " -AddressFamily IPv4 -Type Unicast | Out-Null";

            const std::wstring cmd =
                L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" +
                utf8_to_wstring(script.str()) +
                L"\"";

            DWORD exit_code = 1;
            if (!run_process_wait(cmd, exit_code)) {
                spdlog::error("[wintun] failed to start PowerShell for IPv4 config (GetLastError={})",
                    static_cast<int>(exit_code));
                return false;
            }

            if (exit_code != 0) {
                spdlog::error("[wintun] PowerShell IPv4 config failed (exit={})", static_cast<int>(exit_code));
                return false;
            }

            spdlog::info(
                "[wintun] IPv4 configured: alias='{}' ip={}/{}",
                if_alias,
                ipv4_addr,
                static_cast<int>(ipv4_prefix)
            );
            return true;
        }

    } // namespace

    WintunDevice::WintunDevice() = default;

    WintunDevice::~WintunDevice() {
        stop();
    }

    bool WintunDevice::start(const TunConfig& cfg) {
        if (st_.load() == TunState::Running) {
            return true;
        }

        cfg_ = cfg;

        if (!loader_.load()) {
            spdlog::error("[wintun] cannot load wintun.dll (place it near exe)");
            return false;
        }

        std::wstring nameW(cfg_.name.begin(), cfg_.name.end());

        adapter_ = loader_.WintunCreateAdapter(nameW.c_str(), L"Wintun", nullptr);
        if (!adapter_) {
            spdlog::error("[wintun] WintunCreateAdapter failed (GetLastError={})",
                static_cast<int>(GetLastError()));
            return false;
        }

        constexpr DWORD kRingCapacity = 4 * 1024 * 1024;
        session_ = loader_.WintunStartSession(adapter_, kRingCapacity);
        if (!session_) {
            spdlog::error("[wintun] WintunStartSession failed (GetLastError={})",
                static_cast<int>(GetLastError()));
            loader_.WintunCloseAdapter(adapter_);
            adapter_ = nullptr;
            return false;
        }

        read_event_ = loader_.WintunGetReadWaitEvent(session_);
        if (!read_event_) {
            spdlog::error("[wintun] WintunGetReadWaitEvent failed");
            loader_.WintunEndSession(session_);
            session_ = nullptr;
            loader_.WintunCloseAdapter(adapter_);
            adapter_ = nullptr;
            return false;
        }

        if (!configure_ipv4_powershell(cfg_.name, cfg_.ipv4_addr, cfg_.ipv4_prefix)) {
            spdlog::error(
                "[wintun] failed to configure IPv4 on interface '{}', requested {}/{}",
                cfg_.name,
                cfg_.ipv4_addr,
                static_cast<int>(cfg_.ipv4_prefix)
            );

            loader_.WintunEndSession(session_);
            session_ = nullptr;
            loader_.WintunCloseAdapter(adapter_);
            adapter_ = nullptr;
            read_event_ = nullptr;
            return false;
        }

        running_.store(true);
        st_.store(TunState::Running);

        rx_thread_ = std::thread([this]() {
            rx_loop();
            });

        spdlog::info("[wintun] adapter created: {}", cfg_.name);
        return true;
    }

    void WintunDevice::stop() {
        if (st_.load() == TunState::Stopped) {
            return;
        }

        running_.store(false);
        st_.store(TunState::Stopped);

        if (read_event_) {
            SetEvent(read_event_);
        }

        if (rx_thread_.joinable()) {
            rx_thread_.join();
        }

        if (session_) {
            loader_.WintunEndSession(session_);
            session_ = nullptr;
        }

        if (adapter_) {
            loader_.WintunCloseAdapter(adapter_);
            adapter_ = nullptr;
        }

        read_event_ = nullptr;
    }

    TunState WintunDevice::state() const {
        return st_.load();
    }

    void WintunDevice::set_read_handler(ReadHandler cb) {
        std::lock_guard lock(mtx_);
        on_read_ = std::move(cb);
    }

    bool WintunDevice::write(Packet pkt) {
        if (st_.load() != TunState::Running || !session_) {
            return false;
        }

        if (pkt.empty()) {
            return true;
        }

        BYTE* buf = loader_.WintunAllocateSendPacket(session_, static_cast<DWORD>(pkt.size()));
        if (!buf) {
            return false;
        }

        std::memcpy(buf, pkt.data(), pkt.size());
        loader_.WintunSendPacket(session_, buf);

        out_pkts_.fetch_add(1);
        out_bytes_.fetch_add(pkt.size());
        return true;
    }

    TunStats WintunDevice::stats() const {
        TunStats s;
        s.packets_in = in_pkts_.load();
        s.packets_out = out_pkts_.load();
        s.bytes_in = in_bytes_.load();
        s.bytes_out = out_bytes_.load();
        return s;
    }

    void WintunDevice::rx_loop() {
        while (running_.load()) {
            WaitForSingleObject(read_event_, INFINITE);

            if (!running_.load()) {
                break;
            }

            while (running_.load()) {
                DWORD size = 0;
                BYTE* pkt = loader_.WintunReceivePacket(session_, &size);
                if (!pkt) {
                    DWORD err = GetLastError();
                    if (err == ERROR_NO_MORE_ITEMS) {
                        break;
                    }

                    spdlog::warn("[wintun] ReceivePacket failed (GetLastError={})",
                        static_cast<int>(err));
                    break;
                }

                Packet data;
                data.resize(size);
                std::memcpy(data.data(), pkt, size);

                loader_.WintunReleaseReceivePacket(session_, pkt);

                in_pkts_.fetch_add(1);
                in_bytes_.fetch_add(size);

                ReadHandler cb;
                {
                    std::lock_guard lock(mtx_);
                    cb = on_read_;
                }

                if (cb) {
                    try {
                        cb(std::move(data));
                    }
                    catch (...) {
                    }
                }
            }
        }
    }

} // namespace proxycore::pal

#endif // _WIN32