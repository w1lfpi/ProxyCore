#include "tcp_relay.hpp"
#include <spdlog/spdlog.h>

namespace proxycore::net {

    TcpRelay::TcpRelay(tcp::socket a, tcp::socket b, std::chrono::seconds idle_timeout)
        : a_(std::move(a))
        , b_(std::move(b))
        , timer_(a_.get_executor())
        , idle_timeout_(idle_timeout) {
    }

    void TcpRelay::start() {
        touch();
        pump_a_to_b();
        pump_b_to_a();
    }

    void TcpRelay::touch() {
        arm_timer();
    }

    void TcpRelay::arm_timer() {
        timer_.expires_after(idle_timeout_);
        auto self = shared_from_this();
        timer_.async_wait([this, self](const boost::system::error_code& ec) { on_timeout(ec); });
    }

    void TcpRelay::on_timeout(const boost::system::error_code& ec) {
        if (ec) return; // cancelled
        spdlog::info("[relay] idle timeout, closing");
        shutdown_and_close();
    }

    void TcpRelay::shutdown_and_close() {
        if (closed_) return;
        closed_ = true;

        // В этой версии Boost.Asio cancel() без error_code
        timer_.cancel();

        boost::system::error_code ig;
        a_.shutdown(tcp::socket::shutdown_both, ig);
        b_.shutdown(tcp::socket::shutdown_both, ig);
        a_.close(ig);
        b_.close(ig);
    }

    void TcpRelay::pump_a_to_b() {
        auto self = shared_from_this();
        a_.async_read_some(boost::asio::buffer(buf_ab_),
            [this, self](const boost::system::error_code& ec, std::size_t n) {
                if (ec || n == 0) { shutdown_and_close(); return; }
                touch();
                boost::asio::async_write(b_, boost::asio::buffer(buf_ab_.data(), n),
                    [this, self](const boost::system::error_code& ec2, std::size_t) {
                        if (ec2) { shutdown_and_close(); return; }
                        touch();
                        pump_a_to_b();
                    });
            });
    }

    void TcpRelay::pump_b_to_a() {
        auto self = shared_from_this();
        b_.async_read_some(boost::asio::buffer(buf_ba_),
            [this, self](const boost::system::error_code& ec, std::size_t n) {
                if (ec || n == 0) { shutdown_and_close(); return; }
                touch();
                boost::asio::async_write(a_, boost::asio::buffer(buf_ba_.data(), n),
                    [this, self](const boost::system::error_code& ec2, std::size_t) {
                        if (ec2) { shutdown_and_close(); return; }
                        touch();
                        pump_b_to_a();
                    });
            });
    }

} // namespace proxycore::net