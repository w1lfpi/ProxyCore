#include "clash/clash_yaml_importer.hpp"

#include <fmt/core.h>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: clash_dump <path-to-clash.yaml>\n";
        return 2;
    }

    try {
        const auto doc = proxycore::clash::ClashYamlImporter::load_from_file(argv[1]);

        fmt::print("proxies: {}\n", doc.proxies.size());
        for (const auto& p : doc.proxies) {
            fmt::print(" - name: {}\n", p.name);
            fmt::print("   type: {}\n", p.type);
            fmt::print("   server: {}:{}\n", p.wg.server, p.wg.port);
            fmt::print("   ip: {}\n", p.wg.ip);
            if (!p.wg.reserved.empty()) {
                fmt::print("   reserved: [{}, {}, {}]\n",
                    p.wg.reserved.size() > 0 ? p.wg.reserved[0] : 0,
                    p.wg.reserved.size() > 1 ? p.wg.reserved[1] : 0,
                    p.wg.reserved.size() > 2 ? p.wg.reserved[2] : 0);
            }
            if (p.awg.has_value()) {
                fmt::print("   amnezia-wg-option: jc={} jmin={} jmax={}\n",
                    p.awg->jc, p.awg->jmin, p.awg->jmax);
            }
        }

        fmt::print("\nproxy-groups: {}\n", doc.groups.size());
        for (const auto& g : doc.groups) {
            fmt::print(" - name: {} (type={}) proxies={}\n", g.name, g.type, g.proxies.size());
        }

        return 0;
    }
    catch (const std::exception& ex) {
        std::cout << "error: " << ex.what() << "\n";
        return 1;
    }
}