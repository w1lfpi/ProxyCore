#include "wintun_loader.hpp"

#if defined(_WIN32)

#include <string>

namespace proxycore::pal {

    WintunLoader::WintunLoader() = default;
    WintunLoader::~WintunLoader() { unload(); }

    HMODULE WintunLoader::load_from_exe_dir() {
        WCHAR path[MAX_PATH]{};
        DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return nullptr;

        std::wstring p(path);
        auto pos = p.find_last_of(L"\\/");
        if (pos == std::wstring::npos) return nullptr;

        std::wstring dir = p.substr(0, pos);
        std::wstring dll = dir + L"\\wintun.dll";
        return LoadLibraryW(dll.c_str());
    }

    bool WintunLoader::load() {
        if (module_) return true;

        module_ = load_from_exe_dir();
        if (!module_) {
            module_ = LoadLibraryW(L"wintun.dll");
        }
        if (!module_) return false;

        if (!resolve_all()) {
            unload();
            return false;
        }
        return true;
    }

    void WintunLoader::unload() {
        if (module_) {
            FreeLibrary(module_);
            module_ = nullptr;
        }
    }

    bool WintunLoader::resolve_all() {
#define RESOLVE(name) \
    do { \
        name = reinterpret_cast<decltype(name)>(GetProcAddress(module_, #name)); \
        if (!name) return false; \
    } while (0)

        RESOLVE(WintunCreateAdapter);
        RESOLVE(WintunOpenAdapter);
        RESOLVE(WintunCloseAdapter);

        RESOLVE(WintunStartSession);
        RESOLVE(WintunEndSession);

        RESOLVE(WintunGetReadWaitEvent);
        RESOLVE(WintunReceivePacket);
        RESOLVE(WintunReleaseReceivePacket);
        RESOLVE(WintunAllocateSendPacket);
        RESOLVE(WintunSendPacket);

#undef RESOLVE
        return true;
    }

} // namespace proxycore::pal

#endif // _WIN32