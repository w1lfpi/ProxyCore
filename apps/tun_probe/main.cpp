#include "pal/pal_factory.hpp"
#include <spdlog/spdlog.h>

#include <chrono>
#include <thread>

int main() {
    auto tun = proxycore::pal::PalFactory::create_tun();
    if (!tun) {
        spdlog::error("[tun_probe] TUN not supported on this platform (factory returned null)");
        return 1;
    }

    proxycore::pal::TunConfig cfg;
    cfg.name = "proxycore-tun-probe";

    if (!tun->start(cfg)) {
        spdlog::error("[tun_probe] start failed");
        return 1;
    }

    spdlog::info("[tun_probe] started (stub). sleeping 3 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(3));

    auto st = tun->stats();
    spdlog::info("[tun_probe] stats: in_pkts={} out_pkts={} in_bytes={} out_bytes={}",
        st.packets_in, st.packets_out, st.bytes_in, st.bytes_out);

    tun->stop();
    spdlog::info("[tun_probe] stopped");
    return 0;
}