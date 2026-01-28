#pragma once
#include <memory>

#include "proxycore/pal/tun.hpp"

namespace proxycore::pal {

    class PalFactory {
    public:
        static TunDevicePtr create_tun();
    };

} // namespace proxycore::pal