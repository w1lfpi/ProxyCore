#pragma once
#include <atomic>
#include <mutex>

#include "proxycore/pal/tun.hpp"

namespace proxycore::pal {

    // Заглушка. Позже заменим на реальный Wintun loader + read/write через Wintun API.
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
        std::atomic<TunState> st_{ TunState::Stopped };
        mutable std::mutex mtx_;
        ReadHandler on_read_;

        TunStats stats_{};
        TunConfig cfg_{};
    };

} // namespace proxycore::pal