#pragma once
#include <array>
#include <cstdint>
#include <memory>

#include <boost/asio.hpp>

namespace proxycore::net {

    class TcpRelay : public std::enable_shared_from_this<TcpRelay> {
    public:
        using tcp = boost::asio::ip::tcp;

        TcpRelay(tcp::socket a, tcp::socket b,
            std::chrono::seconds idle_timeout = std::chrono::seconds(120));

        void start();

    private:
        void pump_a_to_b();
        void pump_b_to_a();

        void touch();
        void arm_timer();
        void on_timeout(const boost::system::error_code& ec);
        void shutdown_and_close();

        tcp::socket a_;
        tcp::socket b_;
        boost::asio::steady_timer timer_;
        std::chrono::seconds idle_timeout_;

        std::array<std::uint8_t, 32 * 1024> buf_ab_{};
        std::array<std::uint8_t, 32 * 1024> buf_ba_{};
        bool closed_ = false;
    };

} // namespace proxycore::net