#
# SPDX-License-Identifier: LicenseRef-MSLA
# Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
#
# The licensor of this software is Silicon Laboratories Inc. Your use of this
# software is governed by the terms of the Silicon Labs Master Software License
# Agreement (MSLA) available at [1].  This software is distributed to you in
# Object Code format and/or Source Code format and is governed by the sections
# of the MSLA applicable to Object Code, Source Code and Modified Open Source
# Code. By using this software, you agree to the terms of the MSLA.
#
# [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
#
cmake_minimum_required(VERSION  3.16.3)
project(wsbrd)
set(COMPILE_DEVTOOLS OFF CACHE BOOL "Keep unset if you don't consider to develop new features")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GNUInstallDirs)

include(CheckCCompilerFlag)
check_c_compiler_flag(-Wall                  CC_HAVE_WALL)
check_c_compiler_flag(-Wno-format-zero-length CC_HAVE_WNO_FORMAT_ZERO_LENGTH)
check_c_compiler_flag(-Wno-stringop-overread CC_HAVE_WNO_STRINGOP_OVERREAD)
check_c_compiler_flag(-Wno-stringop-overflow CC_HAVE_WNO_STRINGOP_OVERFLOW)
check_c_compiler_flag(-funwind-tables        CC_HAVE_UNWIND_TABLES)
check_c_compiler_flag(-rdynamic              CC_HAVE_RDYNAMIC)

include(CheckIncludeFile)
check_include_file(sl_cpc.h LIBCPC_FOUND)
# Depending of the distribution backtrace.h may be packaged with gcc. Else,
# the libbacktrace project provides a fully compatible library.
check_include_file(backtrace.h BACKTRACE_FOUND)

check_include_file(sys/queue.h SYSQUEUE_FOUND)
if(NOT SYSQUEUE_FOUND)
    message(FATAL_ERROR "wsbrd needs sys/queue.h")
endif()

include(CheckSymbolExists)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(dladdr dlfcn.h LIBDL_FOUND)
unset(CMAKE_REQUIRED_DEFINITIONS)
unset(CMAKE_REQUIRED_LIBRARIES)

find_package(Rust 1.38)
find_package(Cargo 1.38)

find_package(ns3 QUIET)
mark_as_advanced(ns3_DIR)
if(ns3_FOUND)
    # The wsbrd simulation library only works with a ns-3 fork private to
    # Silicon Labs. See app_wsbrd_ns3/README.md.
    include(CheckIncludeFileCXX)
    get_target_property(NS3_INCLUDE_DIRECTORIES ns3::libcore INTERFACE_INCLUDE_DIRECTORIES)
    set(CMAKE_REQUIRED_INCLUDES ${NS3_INCLUDE_DIRECTORIES})
    set(CMAKE_REQUIRED_QUIET ON)
    unset(ns3_FOUND)
    check_include_file_cxx(ns3/sl-wisun-linux.hpp ns3_FOUND)
    unset(CMAKE_REQUIRED_QUIET)
    unset(CMAKE_REQUIRED_INCLUDES)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

# Syntax "MbedTLS 2.18...<4" does not work :(
find_package(MbedTLS REQUIRED)
mark_as_advanced(MbedTLS_DIR)

# Check if MbedTLS has been compiled with -fPIC
set(CMAKE_REQUIRED_LIBRARIES MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
set(CMAKE_REQUIRED_LINK_OPTIONS ${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS})
set(CMAKE_REQUIRED_QUIET True)
check_symbol_exists(mbedtls_ssl_session_init mbedtls/ssl.h MBEDTLS_COMPILED_WITH_PIC)
unset(CMAKE_REQUIRED_QUIET)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
unset(CMAKE_REQUIRED_LIBRARIES)
if(MBEDTLS_COMPILED_WITH_PIC)
    set_target_properties(MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 PROPERTIES POSITION_INDEPENDENT_CODE True)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCAP               IMPORTED_TARGET libcap>=2.29)
pkg_check_modules(LIBSYSTEMD           IMPORTED_TARGET libsystemd)
pkg_check_modules(LIBNL_ROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)

# Greatly improve warning messages. There is no reason to not enable that.
if(CC_HAVE_WALL)
    add_compile_options(-Wall)
endif()

# ... but it generate two irrelevant warnings
if(CC_HAVE_WNO_FORMAT_ZERO_LENGTH)
    add_compile_options(-Wno-format-zero-length)
endif()
if(CC_HAVE_WNO_STRINGOP_OVERREAD)
    add_compile_options(-Wno-stringop-overread)
endif()
if(CC_HAVE_WNO_STRINGOP_OVERFLOW)
    add_compile_options(-Wno-stringop-overflow)
endif()

# Ask to glibc to check buffer overflows in memcpy() and friends.
add_compile_definitions(_FORTIFY_SOURCE=3)

# In come case, backtraces are not available without that flags. Increase size
# of the  binary file, but can be stripped.
if(CC_HAVE_UNWIND_TABLES)
    add_compile_options(-funwind-tables)
endif()

# -rdynamic improves backtraces when debugs symbols are not available. Slightly
# increase size of the binary file (can be stripped?).
if(CC_HAVE_RDYNAMIC AND LIBDL_FOUND)
    add_link_options(-rdynamic)
endif()

add_custom_target(check_git
    ALL
    BYPRODUCTS version.c
    COMMENT "Checking the git repository for changes..."
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/version.sh ${CMAKE_CURRENT_LIST_DIR} version.c)

add_library(libwsbrd STATIC
    version.c
    app_wsbrd/app/wsbrd.c
    app_wsbrd/app/wsbr_cfg.c
    app_wsbrd/app/wsbr_mac.c
    app_wsbrd/app/wsbr_pcapng.c
    app_wsbrd/app/rail_config.c
    app_wsbrd/app/timers.c
    app_wsbrd/app/tun.c
    app_wsbrd/app/commandline.c
    app_wsbrd/app/commandline_values.c
    common/crypto/ieee80211.c
    common/crypto/hmac_md.c
    common/crypto/nist_kw.c
    common/crypto/ws_keys.c
    common/crc.c
    common/bus_uart.c
    common/capture.c
    common/commandline.c
    common/dbus.c
    common/events_scheduler.c
    common/log.c
    common/bits.c
    common/endian.c
    common/rand.c
    common/mbedtls_config_check.c
    common/named_values.c
    common/fnv_hash.c
    common/parsers.c
    common/pcapng.c
    common/dhcp_server.c
    common/dhcp_common.c
    common/iobuf.c
    common/ipv6_flow_label.c
    common/hif.c
    common/spinel.c
    common/trickle_legacy.c
    common/ws_chan_mask.c
    common/ws_regdb.c
    common/key_value_storage.c
    common/ieee802154_frame.c
    common/ieee802154_ie.c
    common/mpx.c
    common/time_extra.c
    common/random_early_detection.c
    common/rail_config.c
    common/rcp_api.c
    common/timer.c
    common/tun.c
    common/ws_ie.c
    common/ws_neigh.c
    app_wsbrd/6lowpan/lowpan_adaptation_interface.c
    app_wsbrd/6lowpan/bootstraps/protocol_6lowpan.c
    app_wsbrd/6lowpan/fragmentation/cipv6_fragmenter.c
    app_wsbrd/6lowpan/iphc_decode/cipv6.c
    app_wsbrd/6lowpan/iphc_decode/iphc_compress.c
    app_wsbrd/6lowpan/iphc_decode/iphc_decompress.c
    app_wsbrd/6lowpan/iphc_decode/lowpan_context.c
    app_wsbrd/6lowpan/mac/mac_helper.c
    app_wsbrd/ipv6/nd_router_object.c
    app_wsbrd/ws/ws_pan_info_storage.c
    app_wsbrd/ws/ws_bootstrap.c
    app_wsbrd/ws/ws_bootstrap_6lbr.c
    app_wsbrd/ws/ws_common.c
    app_wsbrd/ws/ws_eapol_auth_relay.c
    app_wsbrd/ws/ws_eapol_pdu.c
    app_wsbrd/ws/ws_eapol_relay.c
    app_wsbrd/ws/ws_eapol_relay_lib.c
    app_wsbrd/ws/ws_ie_custom.c
    app_wsbrd/ws/ws_ie_validation.c
    app_wsbrd/ws/ws_llc.c
    app_wsbrd/ws/ws_mngt.c
    app_wsbrd/ws/ws_pae_auth.c
    app_wsbrd/ws/ws_pae_controller.c
    app_wsbrd/ws/ws_pae_key_storage.c
    app_wsbrd/ws/ws_pae_lib.c
    app_wsbrd/ipv6/icmpv6.c
    app_wsbrd/ipv6/ipv6.c
    app_wsbrd/ipv6/ipv6_resolution.c
    app_wsbrd/net/timers.c
    app_wsbrd/net/ns_address_internal.c
    app_wsbrd/net/ns_buffer.c
    app_wsbrd/ipv6/ipv6_neigh_storage.c
    app_wsbrd/ipv6/ipv6_routing_table.c
    app_wsbrd/mpl/mpl.c
    app_wsbrd/net/protocol.c
    app_wsbrd/net/protocol_abstract.c
    app_wsbrd/rpl/rpl_glue.c
    app_wsbrd/rpl/rpl_storage.c
    app_wsbrd/rpl/rpl_srh.c
    app_wsbrd/rpl/rpl.c
    app_wsbrd/security/eapol/eapol_helper.c
    app_wsbrd/security/eapol/kde_helper.c
    app_wsbrd/security/kmp/kmp_addr.c
    app_wsbrd/security/kmp/kmp_api.c
    app_wsbrd/security/kmp/kmp_eapol_pdu_if.c
    app_wsbrd/security/kmp/kmp_socket_if.c
    app_wsbrd/security/pana/pana_eap_header.c
    app_wsbrd/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    app_wsbrd/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    app_wsbrd/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    app_wsbrd/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    app_wsbrd/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    app_wsbrd/security/protocols/key_sec_prot/key_sec_prot.c
    app_wsbrd/security/protocols/msg_sec_prot/msg_sec_prot.c
    app_wsbrd/security/protocols/radius_sec_prot/avp_helper.c
    app_wsbrd/security/protocols/radius_sec_prot/radius_client_sec_prot.c
    app_wsbrd/security/protocols/sec_prot_certs.c
    app_wsbrd/security/protocols/sec_prot_keys.c
    app_wsbrd/security/protocols/sec_prot_lib.c
    app_wsbrd/security/protocols/tls_sec_prot/tls_sec_prot.c
    app_wsbrd/security/protocols/tls_sec_prot/tls_sec_prot_lib.c
)
target_include_directories(libwsbrd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    app_wsbrd/
)
# target_compile_definitions(libwsbrd PRIVATE EXTRA_DEBUG_INFO)
target_link_options(libwsbrd PUBLIC -Wl,--wrap=time) # Required by common/capture.c
target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBNL_ROUTE)
target_link_libraries(libwsbrd PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
target_compile_definitions(libwsbrd PUBLIC HAVE_MBEDTLS)
if(LIBCAP_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBCAP)
    target_sources(libwsbrd PRIVATE app_wsbrd/app/drop_privileges.c)
    target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBCAP)
endif()
if(LIBSYSTEMD_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBSYSTEMD)
    target_sources(libwsbrd PRIVATE app_wsbrd/app/dbus.c)
    target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBSYSTEMD)
endif()
if(BACKTRACE_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_BACKTRACE)
    target_sources(libwsbrd PRIVATE common/backtrace_show.c)
    target_link_libraries(libwsbrd PRIVATE backtrace)
endif()
if(LIBDL_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBDL)
    target_link_libraries(libwsbrd PRIVATE ${CMAKE_DL_LIBS})
endif()
if(LIBCPC_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBCPC)
    target_sources(libwsbrd PRIVATE common/bus_cpc.c)
    target_link_libraries(libwsbrd PRIVATE cpc)
endif()
set_target_properties(libwsbrd PROPERTIES OUTPUT_NAME wsbrd)

add_executable(wsbrd app_wsbrd/app/main.c)
add_dependencies(wsbrd libwsbrd)
target_link_libraries(wsbrd libwsbrd)
install(TARGETS wsbrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_library(libwsrd STATIC
    app_wsrd/app/commandline.c
    app_wsrd/app/wsrd.c
    app_wsrd/ipv6/6lowpan.c
    app_wsrd/ipv6/6lowpan_iphc.c
    app_wsrd/ipv6/ipv6.c
    app_wsrd/ipv6/ipv6_addr.c
    app_wsrd/ipv6/ndp.c
    app_wsrd/ipv6/rpl.c
    app_wsrd/ipv6/rpl_mrhof.c
    app_wsrd/supplicant/supplicant_eap.c
    app_wsrd/supplicant/supplicant_key.c
    app_wsrd/supplicant/supplicant.c
    app_wsrd/ws/ws.c
    common/crypto/ieee80211.c
    common/crypto/hmac_md.c
    common/crypto/nist_kw.c
    common/crypto/ws_keys.c
    common/bits.c
    common/bus_uart.c
    common/capture.c
    common/commandline.c
    common/crc.c
    common/dhcp_client.c
    common/dhcp_common.c
    common/eap.c
    common/eapol.c
    common/endian.c
    common/hif.c
    common/ieee802154_frame.c
    common/ieee802154_ie.c
    common/iobuf.c
    common/kde.c
    common/key_value_storage.c
    common/log.c
    common/mbedtls_config_check.c
    common/mpx.c
    common/named_values.c
    common/parsers.c
    common/pktbuf.c
    common/rail_config.c
    common/rand.c
    common/rcp_api.c
    common/rfc8415_txalg.c
    common/timer.c
    common/time_extra.c
    common/trickle.c
    common/tun.c
    common/ws_chan_mask.c
    common/ws_ie.c
    common/ws_neigh.c
    common/ws_regdb.c
    version.c
)
target_include_directories(libwsrd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_options(libwsrd PUBLIC -Wl,--wrap=time) # Required by common/capture.c
target_link_libraries(libwsrd PUBLIC MbedTLS::mbedtls PkgConfig::LIBNL_ROUTE)
target_compile_definitions(libwsrd PUBLIC HAVE_MBEDTLS)
if(LIBSYSTEMD_FOUND)
    target_compile_definitions(libwsrd PRIVATE HAVE_LIBSYSTEMD)
    target_sources(libwsrd PRIVATE common/dbus.c app_wsrd/app/dbus.c)
    target_link_libraries(libwsrd PRIVATE PkgConfig::LIBSYSTEMD)
endif()
if(BACKTRACE_FOUND)
    target_compile_definitions(libwsrd PRIVATE HAVE_BACKTRACE)
    target_sources(libwsrd PRIVATE common/backtrace_show.c)
    target_link_libraries(libwsrd PUBLIC backtrace)
endif()
if(LIBDL_FOUND)
    target_compile_definitions(libwsrd PRIVATE HAVE_LIBDL)
    target_link_libraries(libwsrd PUBLIC ${CMAKE_DL_LIBS})
endif()
if(LIBCPC_FOUND)
    target_compile_definitions(libwsrd PRIVATE HAVE_LIBCPC)
    target_sources(libwsrd PRIVATE common/bus_cpc.c)
    target_link_libraries(libwsrd PUBLIC cpc)
endif()

add_executable(wsrd app_wsrd/app/main.c)
add_dependencies(wsrd libwsrd)
target_link_libraries(wsrd libwsrd)
install(TARGETS wsrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(RUST_FOUND AND CARGO_FOUND AND RUST_VERSION VERSION_GREATER_EQUAL 1.31)

    string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
    if(NOT CMAKE_BUILD_TYPE_UPPER OR CMAKE_BUILD_TYPE_UPPER STREQUAL DEBUG)
        set(RUST_TARGET_DIR cargo/${RUST_TARGET}/debug)
        set(RUST_BUILD_FLAG)
    else()
        set(RUST_TARGET_DIR cargo/${RUST_TARGET}/release)
        set(RUST_BUILD_FLAG --release)
    endif()

    add_custom_target(cargo-wsbrd_cli ALL DEPENDS wsbrd_cli)
    add_custom_command(OUTPUT wsbrd_cli
        COMMAND ${CARGO_COMMAND} build ${RUST_BUILD_FLAG} --target=${RUST_TARGET} --target-dir=cargo/
                                       --manifest-path=${CMAKE_CURRENT_SOURCE_DIR}/tools/wsbrd_cli/Cargo.toml
        COMMAND ${CMAKE_COMMAND} -E copy ${RUST_TARGET_DIR}/wsbrd_cli wsbrd_cli
        DEPENDS tools/wsbrd_cli/Cargo.toml tools/wsbrd_cli/wsbrd_cli.rs tools/wsbrd_cli/wsbrddbusapi.rs
        USES_TERMINAL
    )
    set_target_properties(cargo-wsbrd_cli PROPERTIES ADDITIONAL_CLEAN_FILES cargo)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wsbrd_cli DESTINATION ${CMAKE_INSTALL_BINDIR})

endif()

add_executable(wsbrd-fwup
    tools/fwup/wsbrd_fwup.c
    common/bits.c
    common/log.c
    common/crc.c
    common/bus_uart.c
    common/hif.c
    common/spinel.c
    common/iobuf.c
    common/endian.c
    common/named_values.c
)
target_include_directories(wsbrd-fwup PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS wsbrd-fwup RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(COMPILE_DEVTOOLS)
    add_executable(wsbrd-fuzz
        tools/fuzz/wsbrd_fuzz.c
        tools/fuzz/commandline.c
        tools/fuzz/interfaces.c
        tools/fuzz/replay.c
        tools/fuzz/rand.c
        tools/fuzz/main.c
    )
    target_include_directories(wsbrd-fuzz PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        app_wsbrd/
    )
    add_dependencies(wsbrd-fuzz libwsbrd)
    target_link_libraries(wsbrd-fuzz libwsbrd)
    if(BACKTRACE_FOUND)
        target_compile_definitions(wsbrd-fuzz PRIVATE HAVE_BACKTRACE)
    endif()
    target_link_options(wsbrd-fuzz PRIVATE
        -Wl,--wrap=parse_commandline
        -Wl,--wrap=print_help_br
        -Wl,--wrap=uart_open
        -Wl,--wrap=uart_rx
        -Wl,--wrap=crc_check
        -Wl,--wrap=spinel_prop_is_valid
        -Wl,--wrap=wsbr_tun_init
        -Wl,--wrap=tun_addr_get_uc_global
        -Wl,--wrap=tun_addr_get_linklocal
        -Wl,--wrap=wsbr_common_timer_init
        -Wl,--wrap=clock_gettime
        -Wl,--wrap=read
        -Wl,--wrap=write
        -Wl,--wrap=writev
        -Wl,--wrap=recv
        -Wl,--wrap=recvfrom
        -Wl,--wrap=recvmsg
        -Wl,--wrap=socket
        -Wl,--wrap=setsockopt
        -Wl,--wrap=bind
        -Wl,--wrap=sendto
        -Wl,--wrap=sendmsg
        -Wl,--wrap=xgetrandom
    )
    install(TARGETS wsbrd-fuzz RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(wshwping
        tools/hwping/wshwping.c
        common/bits.c
        common/log.c
        common/crc.c
        common/bus_uart.c
        common/hif.c
        common/spinel.c
        common/named_values.c
        common/iobuf.c
        common/endian.c
    )
    target_include_directories(wshwping PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        app_wsbrd/
    )
    if(LIBCPC_FOUND)
        target_compile_definitions(wshwping PRIVATE HAVE_LIBCPC)
        target_sources(wshwping PRIVATE common/bus_cpc.c)
        target_link_libraries(wshwping PRIVATE cpc)
    endif()
    install(TARGETS wshwping RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    if(ns3_FOUND)
        if (NOT MBEDTLS_COMPILED_WITH_PIC)
            message(FATAL_ERROR "wsbrd-ns3 needs MbedTLS compiled with -fPIC")
        endif()
        if(NOT Threads_FOUND)
            message(FATAL_ERROR "wsbrd-ns3 needs libpthread")
        endif()

        # To embed wsbrd into a shared library to be used with ns-3, dependencies
        # must be compiled with -fPIC. This is also the case for MbedTLS, which
        # cannot be ensured by CMake when resolving dependencies.
        set_property(TARGET libwsbrd PROPERTY POSITION_INDEPENDENT_CODE ON)
        add_library(wsbrd-ns3 SHARED
            tools/simulation/wsbrd_ns3.cpp
            tools/simulation/wsbrd_rand.cpp
            tools/simulation/wsbrd_time.cpp
            tools/simulation/wsbrd_uart.cpp
            tools/fuzz/commandline.c
            tools/fuzz/rand.c
            tools/fuzz/wsbrd_fuzz.c
        )
        # Prevent conflict with bitand()
        target_compile_options(wsbrd-ns3 PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-fno-operator-names>)
        target_include_directories(wsbrd-ns3 PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            app_wsbrd/
            ${NS3_INCLUDE_DIRECTORIES}
        )
        target_link_libraries(wsbrd-ns3 libwsbrd)
        target_link_libraries(wsbrd-ns3 Threads::Threads)
        target_link_options(wsbrd-ns3 PRIVATE
            -Wl,--wrap=uart_open
            -Wl,--wrap=write
            -Wl,--wrap=writev
            -Wl,--wrap=xgetrandom
            -Wl,--wrap=wsbr_common_timer_init
            -Wl,--wrap=wsbr_common_timer_process
            -Wl,--wrap=clock_gettime
            -Wl,--wrap=sigaction
            -Wl,--wrap=exit
            -Wl,--wrap=__tr_printf
        )
        install(TARGETS wsbrd-ns3 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

        set_property(TARGET libwsrd PROPERTY POSITION_INDEPENDENT_CODE ON)
        add_library(wsrd-ns3 SHARED
            tools/simulation/wsrd_ns3.cpp
            tools/simulation/wsrd_time.cpp
            tools/simulation/wsrd_uart.cpp
        )
        # Prevent conflict with bitand()
        target_compile_options(wsrd-ns3 PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-fno-operator-names>)
        target_include_directories(wsrd-ns3 PRIVATE ${NS3_INCLUDE_DIRECTORIES})
        target_link_libraries(wsrd-ns3 libwsrd)
        target_link_libraries(wsrd-ns3 Threads::Threads)
        target_link_options(wsrd-ns3 PRIVATE
            -Wl,--wrap=uart_open
            -Wl,--wrap=writev
            -Wl,--wrap=timerfd_create
            -Wl,--wrap=timerfd_settime
            -Wl,--wrap=clock_gettime
            -Wl,--wrap=signal
            -Wl,--wrap=exit
            -Wl,--wrap=__tr_printf
        )
        install(TARGETS wsrd-ns3 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
endif()

add_custom_command(OUTPUT wsbrd.conf
    COMMAND sed 's: examples/: ${CMAKE_INSTALL_FULL_DOCDIR}/examples/:'
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/wsbrd.conf > wsbrd.conf
    DEPENDS examples/wsbrd.conf)
add_custom_target(examples-wsbrd.conf ALL DEPENDS wsbrd.conf)
install(FILES examples/br_cert.pem examples/br_key.pem examples/ca_cert.pem
              examples/node_cert.pem examples/node_key.pem
              ${CMAKE_CURRENT_BINARY_DIR}/wsbrd.conf
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)
install(FILES CHANGES.md README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES misc/com.silabs.Wisun.BorderRouter.service
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/dbus-1/system-services)
install(FILES misc/com.silabs.Wisun.Router.service
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/dbus-1/system-services)
# systemd does not document /usr/local/lib/systemd/system, but it seems to work
install(FILES misc/wisun-borderrouter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
install(FILES misc/wisun-router.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
# We try to avoid PATH hardcoding, but dbus does not watch
# /usr/local/share/dbus-1/system.d
install(FILES misc/com.silabs.Wisun.BorderRouter.conf
    DESTINATION /etc/dbus-1/system.d)
install(FILES misc/com.silabs.Wisun.Router.conf
    DESTINATION /etc/dbus-1/system.d)
# FIXME: use ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/wsbrd and report this value in
# the code
install(DIRECTORY DESTINATION /var/lib/wsbrd
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ)
install(CODE "execute_process(COMMAND useradd --system --shell /sbin/nologin --home-dir /var/lib/wsbrd wsbrd)")
install(CODE "execute_process(COMMAND chown -R wsbrd:wsbrd /var/lib/wsbrd)")
