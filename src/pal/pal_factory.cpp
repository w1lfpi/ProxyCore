#include "pal_factory.hpp"

#if defined(_WIN32)
#include "windows/wintun_device.hpp"
#endif

namespace proxycore::pal {

    TunDevicePtr PalFactory::create_tun() {
#if defined(_WIN32)
        return std::make_unique<WintunDevice>();
#else
        return nullptr;
#endif
    }

} // namespace proxycore::pal