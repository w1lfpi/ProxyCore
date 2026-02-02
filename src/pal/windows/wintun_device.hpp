#pragma once
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <atomic>
#include <mutex>
#include <thread>

#include "proxycore/pal/tun.hpp"
#include "wintun_loader.hpp"

namespace proxycore::pal {

    class WintunDevice final : public ITunDevice {
    public:
        WintunDevice();
        ~WintunDevice() override;

        bool start(const TunConfig& cfg) override;
        void stop() override;

        TunState state() const override;

        void set_read_handler(ReadHandler cb) override;
        bool write(Packet pkt) override;

        TunStats stats() const override;

    private:
        void rx_loop();

        std::atomic<TunState> st_{ TunState::Stopped };
        std::atomic<bool> running_{ false };

        mutable std::mutex mtx_;
        ReadHandler on_read_;

        std::atomic<std::uint64_t> in_pkts_{ 0 }, out_pkts_{ 0 }, in_bytes_{ 0 }, out_bytes_{ 0 };

        TunConfig cfg_{};

        WintunLoader loader_;
        WintunLoader::WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
        WintunLoader::WINTUN_SESSION_HANDLE session_ = nullptr;
        HANDLE read_event_ = nullptr;

        std::thread rx_thread_;
    };

} // namespace proxycore::pal

#endif // _WIN32