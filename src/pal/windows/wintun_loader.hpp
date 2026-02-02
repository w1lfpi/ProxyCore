#pragma once
#if defined(_WIN32)

#define NOMINMAX
#include <windows.h>
#include <cstdint>

namespace proxycore::pal {

    class WintunLoader {
    public:
        WintunLoader();
        ~WintunLoader();

        WintunLoader(const WintunLoader&) = delete;
        WintunLoader& operator=(const WintunLoader&) = delete;

        bool load();
        void unload();
        bool loaded() const { return module_ != nullptr; }

        using WINTUN_ADAPTER_HANDLE = void*;
        using WINTUN_SESSION_HANDLE = void*;

        using WintunCreateAdapter_t = WINTUN_ADAPTER_HANDLE(WINAPI*)(const WCHAR* Name, const WCHAR* TunnelType, const GUID* RequestedGUID);
        using WintunOpenAdapter_t = WINTUN_ADAPTER_HANDLE(WINAPI*)(const WCHAR* Name);
        using WintunCloseAdapter_t = void (WINAPI*)(WINTUN_ADAPTER_HANDLE Adapter);

        using WintunStartSession_t = WINTUN_SESSION_HANDLE(WINAPI*)(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
        using WintunEndSession_t = void (WINAPI*)(WINTUN_SESSION_HANDLE Session);

        using WintunGetReadWaitEvent_t = HANDLE(WINAPI*)(WINTUN_SESSION_HANDLE Session);
        using WintunReceivePacket_t = BYTE * (WINAPI*)(WINTUN_SESSION_HANDLE Session, DWORD* PacketSize);
        using WintunReleaseReceivePacket_t = void (WINAPI*)(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);
        using WintunAllocateSendPacket_t = BYTE * (WINAPI*)(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
        using WintunSendPacket_t = void (WINAPI*)(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);

        WintunCreateAdapter_t WintunCreateAdapter = nullptr;
        WintunOpenAdapter_t   WintunOpenAdapter = nullptr;
        WintunCloseAdapter_t  WintunCloseAdapter = nullptr;

        WintunStartSession_t  WintunStartSession = nullptr;
        WintunEndSession_t    WintunEndSession = nullptr;

        WintunGetReadWaitEvent_t WintunGetReadWaitEvent = nullptr;
        WintunReceivePacket_t    WintunReceivePacket = nullptr;
        WintunReleaseReceivePacket_t WintunReleaseReceivePacket = nullptr;
        WintunAllocateSendPacket_t WintunAllocateSendPacket = nullptr;
        WintunSendPacket_t        WintunSendPacket = nullptr;

    private:
        HMODULE module_ = nullptr;

        static HMODULE load_from_exe_dir();
        bool resolve_all();
    };

} // namespace proxycore::pal

#endif // _WIN32