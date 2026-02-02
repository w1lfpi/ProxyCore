#include "wintun_device.hpp"

#if defined(_WIN32)

#include <spdlog/spdlog.h>
#include <cstring>

namespace proxycore::pal {

    WintunDevice::WintunDevice() = default;
    WintunDevice::~WintunDevice() { stop(); }

    bool WintunDevice::start(const TunConfig& cfg) {
        if (st_.load() == TunState::Running) return true;

        cfg_ = cfg;

        if (!loader_.load()) {
            spdlog::error("[wintun] cannot load wintun.dll (place it near exe)");
            return false;
        }

        std::wstring nameW(cfg_.name.begin(), cfg_.name.end());
        adapter_ = loader_.WintunCreateAdapter(nameW.c_str(), L"Wintun", nullptr);
        if (!adapter_) {
            spdlog::error("[wintun] WintunCreateAdapter failed (GetLastError={})", (int)GetLastError());
            return false;
        }

        constexpr DWORD kRingCapacity = 4 * 1024 * 1024;
        session_ = loader_.WintunStartSession(adapter_, kRingCapacity);
        if (!session_) {
            spdlog::error("[wintun] WintunStartSession failed (GetLastError={})", (int)GetLastError());
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

        running_.store(true);
        st_.store(TunState::Running);

        rx_thread_ = std::thread([this]() { rx_loop(); });

        spdlog::info("[wintun] adapter created: {}", cfg_.name);
        return true;
    }

    void WintunDevice::stop() {
        if (st_.load() == TunState::Stopped) return;

        running_.store(false);
        st_.store(TunState::Stopped);

        if (read_event_) {
            SetEvent(read_event_);
        }

        if (rx_thread_.joinable()) rx_thread_.join();

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
        std::lock_guard<std::mutex> lock(mtx_);
        on_read_ = std::move(cb);
    }

    bool WintunDevice::write(Packet pkt) {
        if (st_.load() != TunState::Running || !session_) return false;
        if (pkt.empty()) return true;

        BYTE* buf = loader_.WintunAllocateSendPacket(session_, static_cast<DWORD>(pkt.size()));
        if (!buf) return false;

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
            if (!running_.load()) break;

            while (running_.load()) {
                DWORD size = 0;
                BYTE* pkt = loader_.WintunReceivePacket(session_, &size);
                if (!pkt) {
                    DWORD err = GetLastError();
                    if (err == ERROR_NO_MORE_ITEMS) break;
                    spdlog::warn("[wintun] ReceivePacket failed (GetLastError={})", (int)err);
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
                    std::lock_guard<std::mutex> lock(mtx_);
                    cb = on_read_;
                }
                if (cb) {
                    try { cb(std::move(data)); }
                    catch (...) {}
                }
            }
        }
    }

} // namespace proxycore::pal

#endif // _WIN32