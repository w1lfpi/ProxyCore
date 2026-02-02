#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace proxycore::pal {

    struct TunConfig {
        std::string name = "proxycore-tun";

        // Если пусто — адрес не назначаем.
        // Пример: "10.7.0.1", prefix=24
        std::string ipv4_addr;
        std::uint8_t ipv4_prefix = 0;
    };

    enum class TunState : std::uint8_t {
        Stopped = 0,
        Running
    };

    struct TunStats {
        std::uint64_t packets_in = 0;
        std::uint64_t packets_out = 0;
        std::uint64_t bytes_in = 0;
        std::uint64_t bytes_out = 0;
    };

    // Абстракция TUN устройства: read/write IP пакеты (L3).
    class ITunDevice {
    public:
        using Packet = std::vector<std::uint8_t>;
        using ReadHandler = std::function<void(Packet)>;

        virtual ~ITunDevice() = default;

        virtual bool start(const TunConfig& cfg) = 0;
        virtual void stop() = 0;

        virtual TunState state() const = 0;

        // Асинхронная доставка пакетов в callback
        virtual void set_read_handler(ReadHandler cb) = 0;

        // Отправка IP-пакета в интерфейс
        virtual bool write(Packet pkt) = 0;

        virtual TunStats stats() const = 0;
    };

    using TunDevicePtr = std::unique_ptr<ITunDevice>;

} // namespace proxycore::pal