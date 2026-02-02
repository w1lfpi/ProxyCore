cmake_minimum_required(VERSION 3.21)
project(proxy_core LANGUAGES CXX)

option(PROXYCORE_BUILD_CLI "Build CLI app" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_library(proxycore STATIC
  src/engine.cpp
  src/config_manager.cpp
  src/net/socks5_server.cpp
  src/net/tcp_relay.cpp
  src/net/socks5_client.cpp

  src/pal/pal_factory.cpp
  src/pal/windows/wintun_device.cpp
  src/pal/windows/wintun_loader.cpp
)

target_include_directories(proxycore
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(proxycore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if (WIN32)
  target_compile_definitions(proxycore PUBLIC _WIN32_WINNT=0x0A00)
endif()

target_link_libraries(proxycore
  PUBLIC
    Boost::system
    spdlog::spdlog
    fmt::fmt
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
    Threads::Threads
)


if(PROXYCORE_BUILD_CLI)
  add_executable(proxycore_cli
    apps/proxycore_cli/main.cpp
  )
  target_link_libraries(proxycore_cli PRIVATE proxycore)
  if (WIN32)
    target_compile_definitions(proxycore_cli PRIVATE _WIN32_WINNT=0x0A00)
  endif()
endif()

add_executable(socks5_probe
  apps/socks5_probe/main.cpp
)
target_link_libraries(socks5_probe PRIVATE Boost::system Threads::Threads)
if (WIN32)
  target_compile_definitions(socks5_probe PRIVATE _WIN32_WINNT=0x0A00)
endif()

add_library(clash_yaml_importer STATIC
  src/clash/clash_yaml_importer.cpp
)
target_include_directories(clash_yaml_importer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(clash_yaml_importer PUBLIC yaml-cpp::yaml-cpp)
if (WIN32)
  target_compile_definitions(clash_yaml_importer PUBLIC _WIN32_WINNT=0x0A00)
endif()

add_executable(clash_dump
  apps/clash_dump/main.cpp
)
target_link_libraries(clash_dump PRIVATE clash_yaml_importer fmt::fmt)
if (WIN32)
  target_compile_definitions(clash_dump PRIVATE _WIN32_WINNT=0x0A00)
endif()

add_executable(clash_convert
  apps/clash_convert/main.cpp
)
target_link_libraries(clash_convert PRIVATE clash_yaml_importer nlohmann_json::nlohmann_json)
if (WIN32)
  target_compile_definitions(clash_convert PRIVATE _WIN32_WINNT=0x0A00)
endif()

add_executable(tun_probe
  apps/tun_probe/main.cpp
)
target_include_directories(tun_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(tun_probe PRIVATE proxycore)
if (WIN32)
  target_compile_definitions(tun_probe PRIVATE _WIN32_WINNT=0x0A00)
endif()