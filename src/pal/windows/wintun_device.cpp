#include "wintun_device.hpp"

namespace proxycore::pal {

    WintunDevice::WintunDevice() = default;
    WintunDevice::~WintunDevice() { stop(); }

    bool WintunDevice::start(const TunConfig& cfg) {
        if (st_.load() == TunState::Running) return true;
        cfg_ = cfg;
        st_.store(TunState::Running);
        return true; // заглушка: считаем, что “успешно”
    }

    void WintunDevice::stop() {
        st_.store(TunState::Stopped);
    }

    TunState WintunDevice::state() const {
        return st_.load();
    }

    void WintunDevice::set_read_handler(ReadHandler cb) {
        std::lock_guard<std::mutex> lock(mtx_);
        on_read_ = std::move(cb);
    }

    bool WintunDevice::write(Packet pkt) {
        if (st_.load() != TunState::Running) return false;

        // заглушка: просто считаем статистику, пакет никуда не уходит
        stats_.packets_out += 1;
        stats_.bytes_out += static_cast<std::uint64_t>(pkt.size());
        return true;
    }

    TunStats WintunDevice::stats() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return stats_;
    }

} // namespace proxycore::pal