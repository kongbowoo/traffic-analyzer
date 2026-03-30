cmake_minimum_required(VERSION 3.13)
project(dpdk_traffic_analyzer C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3")

# Find DPDK
# Try pkg-config first
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(DPDK libdpdk)
    if(DPDK_FOUND)
        message(STATUS "Found DPDK via pkg-config")
        set(DPDK_INCLUDE_DIRS ${DPDK_INCLUDE_DIRS})
        set(DPDK_LIBRARIES ${DPDK_LIBRARIES})
        set(DPDK_LIBRARY_DIRS ${DPDK_LIBRARY_DIRS})
    endif()
endif()

# If not found via pkg-config, try RTE_SDK/RTE_TARGET environment variables
if(NOT DPDK_FOUND)
    if(DEFINED ENV{RTE_SDK} AND DEFINED ENV{RTE_TARGET})
        set(DPDK_PATH $ENV{RTE_SDK}/$ENV{RTE_TARGET})
    else()
        # Fallback to local DPDK installation
        set(DPDK_PATH ${CMAKE_SOURCE_DIR}/dpdk/dpdk-stable-22.11.1/build)
    endif()

    if(EXISTS ${DPDK_PATH})
        set(DPDK_INCLUDE_DIRS ${DPDK_PATH}/include)
        set(DPDK_LIBRARY_DIRS ${DPDK_PATH}/lib)
        set(DPDK_LIBRARIES dpdk pthread dl m)
        message(STATUS "Found DPDK at: ${DPDK_PATH}")
        message(STATUS "Include dirs: ${DPDK_INCLUDE_DIRS}")
    else()
        message(WARNING "DPDK not found. Please set RTE_SDK/RTE_TARGET or install DPDK.")
        message(WARNING "Falling back to raw socket mode (no DPDK)")
        option(USE_DPDK "Enable DPDK support" OFF)
    endif()
endif()

# Option to enable/disable DPDK
option(USE_DPDK "Enable DPDK support" ON)
if(NOT DPDK_FOUND)
    set(USE_DPDK OFF)
endif()

message(STATUS "USE_DPDK: ${USE_DPDK}")

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/core
    ${CMAKE_SOURCE_DIR}/include/protocol
    ${CMAKE_SOURCE_DIR}/include/analyzer
    ${CMAKE_SOURCE_DIR}/include/stats
    ${CMAKE_SOURCE_DIR}/include/display
    ${CMAKE_SOURCE_DIR}/include/app
)

if(USE_DPDK)
    include_directories(${DPDK_INCLUDE_DIRS})
    link_directories(${DPDK_LIBRARY_DIRS})
endif()

# Source files organized by module
set(CORE_SOURCES
    src/core/hash_table.c
    src/core/types.c
)

set(PROTOCOL_SOURCES
    src/protocol/ethernet.c
    src/protocol/ip.c
    src/protocol/tcp.c
    src/protocol/udp.c
    src/protocol/icmp.c
    src/protocol/dns.c
    src/protocol/tls.c
)

set(ANALYZER_SOURCES
    src/analyzer/flow_table.c
    src/analyzer/ip_table.c
    src/analyzer/fingerprint_table.c
    src/analyzer/geolocation.c
)

set(STATS_SOURCES
    src/stats/counters.c
    src/stats/traffic_stats.c
)

set(DISPLAY_SOURCES
    src/display/formatter.c
    src/display/renderer.c
)

set(APP_SOURCES
    src/app/packet_parser.c
    src/app/stats_collector.c
    src/app/main.c
)

# DPDK adapter source (only if DPDK is enabled)
if(USE_DPDK)
    set(DPDK_SOURCES
        src/dpdk_adapter.c
    )
else()
    # Use old raw socket implementation
    set(OLD_SOURCES
        src/main.c
        src/packet_parser.c
        src/flow_analyzer.c
        src/stats_collector.c
        src/display.c
    )
endif()

# Create library for each module (optional, for better organization)
add_library(core_lib STATIC ${CORE_SOURCES})
add_library(protocol_lib STATIC ${PROTOCOL_SOURCES})
add_library(analyzer_lib STATIC ${ANALYZER_SOURCES})
add_library(stats_lib STATIC ${STATS_SOURCES})
add_library(display_lib STATIC ${DISPLAY_SOURCES})

if(USE_DPDK)
    add_library(app_lib STATIC ${APP_SOURCES} ${DPDK_SOURCES})
else()
    add_library(app_lib STATIC ${APP_SOURCES})
endif()

# Main executable
if(USE_DPDK)
    add_executable(traffic_analyzer
        ${CORE_SOURCES}
        ${PROTOCOL_SOURCES}
        ${ANALYZER_SOURCES}
        ${STATS_SOURCES}
        ${DISPLAY_SOURCES}
        ${APP_SOURCES}
        ${DPDK_SOURCES}
    )

    target_link_libraries(traffic_analyzer
        ${DPDK_LIBRARIES}
        pthread
        m
    )
else()
    add_executable(traffic_analyzer
        ${OLD_SOURCES}
        ${CORE_SOURCES}
        ${PROTOCOL_SOURCES}
        ${ANALYZER_SOURCES}
        ${STATS_SOURCES}
        ${DISPLAY_SOURCES}
        ${APP_SOURCES}
    )

    target_link_libraries(traffic_analyzer
        pthread
    )
endif()

# Installation
install(TARGETS traffic_analyzer
    RUNTIME DESTINATION bin
)

# Print configuration summary
message(STATUS "")
message(STATUS "===============================================")
message(STATUS "  DPDK Traffic Analyzer Configuration")
message(STATUS "===============================================")
message(STATUS "  Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler:    ${CMAKE_C_COMPILER}")
message(STATUS "  C Flags:       ${CMAKE_C_FLAGS}")
message(STATUS "  Use DPDK:      ${USE_DPDK}")
if(USE_DPDK)
    message(STATUS "  DPDK Path:     ${DPDK_PATH}")
    message(STATUS "  DPDK Libs:     ${DPDK_LIBRARIES}")
endif()
message(STATUS "  Install dir:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "===============================================")
message(STATUS "")

# Custom targets
add_custom_target(info
    COMMAND ${CMAKE_COMMAND} -E echo "DPDK Traffic Analyzer Build Info:"
    COMMAND ${CMAKE_COMMAND} -E echo "  CC:          ${CMAKE_C_COMPILER}"
    COMMAND ${CMAKE_COMMAND} -E echo "  CFLAGS:      ${CMAKE_C_FLAGS}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Use DPDK:      ${USE_DPDK}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Install dir:   ${CMAKE_INSTALL_PREFIX}"
    COMMAND ${CMAKE_COMMAND} -E echo ""
)

add_custom_target(run
    COMMAND ${CMAKE_COMMAND} -E echo "Run with: sudo ./traffic_analyzer -c 0x3 -n 4 -- --port 0000:00:01.0"
    DEPENDS traffic_analyzer
)

add_custom_target(test
    COMMAND ${CMAKE_COMMAND} -E echo "Running traffic analyzer in background..."
    COMMAND ${CMAKE_COMMAND} -E echo "Generating test traffic..."
    DEPENDS traffic_analyzer
)

add_custom_target(clean-huge
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning DPDK hugepages..."
    COMMAND ${CMAKE_COMMAND} -E echo "Run: sudo rm -rf /mnt/huge/*"
)

add_custom_target(setup-huge
    COMMAND ${CMAKE_COMMAND} -E echo "Setting up DPDK hugepages..."
    COMMAND ${CMAKE_COMMAND} -E echo "Run: sudo mkdir -p /mnt/huge"
    COMMAND ${CMAKE_COMMAND} -E echo "Run: sudo mount -t hugetlbfs nodev /mnt/huge 2>/dev/null || true"
    COMMAND ${CMAKE_COMMAND} -E echo "Run: echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
)