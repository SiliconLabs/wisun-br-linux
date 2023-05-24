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

include(CheckSymbolExists)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(dladdr dlfcn.h LIBDL_FOUND)
unset(CMAKE_REQUIRED_DEFINITIONS)
unset(CMAKE_REQUIRED_LIBRARIES)

find_package(Rust)
find_package(Cargo)

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
    check_include_file_cxx(ns3/libwsbrd-ns3.hpp ns3_FOUND)
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
# Note that old libpcap releases didn't provide pkg-config file and are not
# detected by the line below. The user have to compile without support for
# libpcap or manually defines the flags.
pkg_check_modules(LIBCAP               IMPORTED_TARGET libcap>=2.29)
pkg_check_modules(LIBPCAP              IMPORTED_TARGET libpcap)
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
    app_wsbrd/wsbr.c
    app_wsbrd/wsbr_mac.c
    app_wsbrd/wsbr_pcapng.c
    app_wsbrd/frame_helpers.c
    app_wsbrd/rail_config.c
    app_wsbrd/rcp_api.c
    app_wsbrd/timers.c
    app_wsbrd/tun.c
    app_wsbrd/commandline.c
    app_wsbrd/commandline_values.c
    app_wsbrd/mbedtls_config_check.c
    common/crc.c
    common/bus_uart.c
    common/events_scheduler.c
    common/log.c
    common/bits.c
    common/endian.c
    common/rand.c
    common/named_values.c
    common/parsers.c
    common/pcapng.c
    common/dhcp_server.c
    common/iobuf.c
    common/spinel_buffer.c
    common/trickle.c
    common/ws_regdb.c
    common/key_value_storage.c
    common/ieee802154_ie.c
    stack/source/timers.c
    stack/source/6lowpan/adaptation_interface.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
    stack/source/6lowpan/fragmentation/cipv6_fragmenter.c
    stack/source/6lowpan/iphc_decode/6lowpan_iphc.c
    stack/source/6lowpan/iphc_decode/iphc_compress.c
    stack/source/6lowpan/iphc_decode/iphc_decompress.c
    stack/source/6lowpan/iphc_decode/lowpan_context.c
    stack/source/6lowpan/mac/mac_helper.c
    stack/source/6lowpan/nd/nd_router_object.c
    stack/source/6lowpan/ws/ws_bbr_api.c
    stack/source/6lowpan/ws/ws_bootstrap.c
    stack/source/6lowpan/ws/ws_bootstrap_6lbr.c
    stack/source/6lowpan/ws/ws_cfg_settings.c
    stack/source/6lowpan/ws/ws_common.c
    stack/source/6lowpan/ws/ws_eapol_auth_relay.c
    stack/source/6lowpan/ws/ws_eapol_pdu.c
    stack/source/6lowpan/ws/ws_eapol_relay.c
    stack/source/6lowpan/ws/ws_eapol_relay_lib.c
    stack/source/6lowpan/ws/ws_ie_lib.c
    stack/source/6lowpan/ws/ws_ie_validation.c
    stack/source/6lowpan/ws/ws_llc_data_service.c
    stack/source/6lowpan/ws/ws_management_api.c
    stack/source/6lowpan/ws/ws_mngt.c
    stack/source/6lowpan/ws/ws_mpx_header.c
    stack/source/6lowpan/ws/ws_neighbor_class.c
    stack/source/6lowpan/ws/ws_pae_auth.c
    stack/source/6lowpan/ws/ws_pae_controller.c
    stack/source/6lowpan/ws/ws_pae_key_storage.c
    stack/source/6lowpan/ws/ws_pae_lib.c
    stack/source/6lowpan/ws/ws_pae_time.c
    stack/source/6lowpan/ws/ws_pae_timers.c
    stack/source/6lowpan/ws/ws_regulation.c
    stack/source/6lowpan/ws/ws_stats.c
    stack/source/6lowpan/ws/ws_test_api.c
    stack/source/common_protocols/icmpv6.c
    stack/source/common_protocols/icmpv6_prefix.c
    stack/source/common_protocols/ipv6.c
    stack/source/common_protocols/ipv6_flow.c
    stack/source/common_protocols/ipv6_resolution.c
    stack/source/core/ns_address_internal.c
    stack/source/core/ns_buffer.c
    stack/source/ipv6_stack/ipv6_routing_table.c
    stack/source/net_api/net_multicast.c
    stack/source/net_api/net_6lowpan_parameter.c
    stack/source/net_api/net_rpl.c
    stack/source/net_api/net_interface.c
    stack/source/net_api/net_ipv6.c
    stack/source/mpl/mpl.c
    stack/source/nwk_interface/protocol_core.c
    stack/source/nwk_interface/protocol_stats.c
    stack/source/rpl/rpl_control.c
    stack/source/rpl/rpl_mrhof.c
    stack/source/rpl/rpl_downward.c
    stack/source/rpl/rpl_data.c
    stack/source/rpl/rpl_objective.c
    stack/source/rpl/rpl_of0.c
    stack/source/rpl/rpl_policy.c
    stack/source/rpl/rpl_upward.c
    stack/source/security/eapol/eapol_helper.c
    stack/source/security/eapol/kde_helper.c
    stack/source/security/kmp/kmp_addr.c
    stack/source/security/kmp/kmp_api.c
    stack/source/security/kmp/kmp_eapol_pdu_if.c
    stack/source/security/kmp/kmp_socket_if.c
    stack/source/security/pana/pana_eap_header.c
    stack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    stack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    stack/source/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    stack/source/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    stack/source/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    stack/source/security/protocols/key_sec_prot/key_sec_prot.c
    stack/source/security/protocols/msg_sec_prot/msg_sec_prot.c
    stack/source/security/protocols/radius_sec_prot/avp_helper.c
    stack/source/security/protocols/radius_sec_prot/radius_client_sec_prot.c
    stack/source/security/protocols/sec_prot_certs.c
    stack/source/security/protocols/sec_prot_keys.c
    stack/source/security/protocols/sec_prot_lib.c
    stack/source/security/protocols/tls_sec_prot/tls_sec_prot.c
    stack/source/security/protocols/tls_sec_prot/tls_sec_prot_lib.c
    stack/source/service_libs/blacklist/blacklist.c
    stack/source/service_libs/etx/etx.c
    stack/source/service_libs/fnv_hash/fnv_hash.c
    stack/source/service_libs/hmac/hmac_md.c
    stack/source/service_libs/ieee_802_11/ieee_802_11.c
    stack/source/service_libs/mac_neighbor_table/mac_neighbor_table.c
    stack/source/service_libs/nist_aes_kw/nist_aes_kw.c
    stack/source/service_libs/random_early_detection/random_early_detection.c
)
target_include_directories(libwsbrd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    stack/source/
    stack/
)
target_compile_options(libwsbrd PRIVATE -include stack/source/configs/cfg_ws_border_router.h)
# target_compile_definitions(libwsbrd PRIVATE EXTRA_DEBUG_INFO)
target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBNL_ROUTE)
target_link_libraries(libwsbrd PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
if(LIBCAP_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBCAP)
    target_sources(libwsbrd PRIVATE app_wsbrd/drop_privileges.c)
    target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBCAP)
endif()
if(LIBSYSTEMD_FOUND)
    target_compile_definitions(libwsbrd PRIVATE HAVE_LIBSYSTEMD)
    target_sources(libwsbrd PRIVATE app_wsbrd/dbus.c)
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

add_executable(wsbrd app_wsbrd/wsbrd.c)
add_dependencies(wsbrd libwsbrd)
target_link_libraries(wsbrd libwsbrd)
install(TARGETS wsbrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

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
    common/spinel_buffer.c
    common/iobuf.c
    common/endian.c
)
target_include_directories(wsbrd-fwup PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS wsbrd-fwup RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(COMPILE_DEVTOOLS)

    add_executable(wsnode
        version.c
        app_wsbrd/wsrouter.c
        app_wsbrd/wsbr_mac.c
        app_wsbrd/wsbr_pcapng.c
        app_wsbrd/frame_helpers.c
        app_wsbrd/rail_config.c
        app_wsbrd/rcp_api.c
        app_wsbrd/timers.c
        app_wsbrd/commandline.c
        app_wsbrd/commandline_values.c
        common/crc.c
        common/bus_uart.c
        common/events_scheduler.c
        common/log.c
        common/bits.c
        common/endian.c
        common/rand.c
        common/named_values.c
        common/parsers.c
        common/pcapng.c
        common/iobuf.c
        common/spinel_buffer.c
        common/trickle.c
        common/ws_regdb.c
        common/key_value_storage.c
        common/ieee802154_ie.c
        stack/source/timers.c
        stack/source/6lowpan/adaptation_interface.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
        stack/source/6lowpan/fragmentation/cipv6_fragmenter.c
        stack/source/6lowpan/iphc_decode/6lowpan_iphc.c
        stack/source/6lowpan/iphc_decode/iphc_compress.c
        stack/source/6lowpan/iphc_decode/iphc_decompress.c
        stack/source/6lowpan/iphc_decode/lowpan_context.c
        stack/source/6lowpan/mac/mac_helper.c
        stack/source/6lowpan/nd/nd_router_object.c
        stack/source/6lowpan/ws/ws_bootstrap.c
        stack/source/6lowpan/ws/ws_bootstrap_ffn.c
        stack/source/6lowpan/ws/ws_cfg_settings.c
        stack/source/6lowpan/ws/ws_common.c
        stack/source/6lowpan/ws/ws_eapol_auth_relay.c
        stack/source/6lowpan/ws/ws_eapol_pdu.c
        stack/source/6lowpan/ws/ws_eapol_relay.c
        stack/source/6lowpan/ws/ws_eapol_relay_lib.c
        stack/source/6lowpan/ws/ws_ie_lib.c
        stack/source/6lowpan/ws/ws_ie_validation.c
        stack/source/6lowpan/ws/ws_llc_data_service.c
        stack/source/6lowpan/ws/ws_management_api.c
        stack/source/6lowpan/ws/ws_mpx_header.c
        stack/source/6lowpan/ws/ws_neighbor_class.c
        stack/source/6lowpan/ws/ws_pae_controller.c
        stack/source/6lowpan/ws/ws_pae_key_storage.c
        stack/source/6lowpan/ws/ws_pae_lib.c
        stack/source/6lowpan/ws/ws_pae_supp.c
        stack/source/6lowpan/ws/ws_pae_time.c
        stack/source/6lowpan/ws/ws_pae_timers.c
        stack/source/6lowpan/ws/ws_regulation.c
        stack/source/6lowpan/ws/ws_stats.c
        stack/source/6lowpan/ws/ws_test_api.c
        stack/source/common_protocols/icmpv6.c
        stack/source/common_protocols/icmpv6_prefix.c
        stack/source/common_protocols/ipv6.c
        stack/source/common_protocols/ipv6_flow.c
        stack/source/common_protocols/ipv6_resolution.c
        stack/source/core/ns_address_internal.c
        stack/source/core/ns_buffer.c
        stack/source/ipv6_stack/ipv6_routing_table.c
        stack/source/legacy/dhcpv6_client.c
        stack/source/legacy/dhcpv6_service.c
        stack/source/legacy/dhcpv6_utils.c
        stack/source/legacy/ipv6_fragmentation_tx.c
        stack/source/legacy/ipv6_fragmentation_rx.c
        stack/source/legacy/net_socket.c
        stack/source/legacy/ns_socket.c
        stack/source/legacy/sockbuf.c
        stack/source/legacy/udp.c
        stack/source/net_api/net_multicast.c
        stack/source/net_api/net_6lowpan_parameter.c
        stack/source/net_api/net_rpl.c
        stack/source/net_api/net_interface.c
        stack/source/net_api/net_ipv6.c
        stack/source/mpl/mpl.c
        stack/source/nwk_interface/protocol_core.c
        stack/source/nwk_interface/protocol_stats.c
        stack/source/rpl/rpl_control.c
        stack/source/rpl/rpl_mrhof.c
        stack/source/rpl/rpl_downward.c
        stack/source/rpl/rpl_data.c
        stack/source/rpl/rpl_objective.c
        stack/source/rpl/rpl_of0.c
        stack/source/rpl/rpl_policy.c
        stack/source/rpl/rpl_upward.c
        stack/source/security/eapol/eapol_helper.c
        stack/source/security/eapol/kde_helper.c
        stack/source/security/kmp/kmp_addr.c
        stack/source/security/kmp/kmp_api.c
        stack/source/security/kmp/kmp_eapol_pdu_if.c
        stack/source/security/kmp/kmp_socket_if.c
        stack/source/security/pana/pana_eap_header.c
        stack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
        stack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
        stack/source/security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
        stack/source/security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
        stack/source/security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
        stack/source/security/protocols/key_sec_prot/key_sec_prot.c
        stack/source/security/protocols/msg_sec_prot/msg_sec_prot.c
        stack/source/security/protocols/radius_sec_prot/avp_helper.c
        stack/source/security/protocols/radius_sec_prot/radius_client_sec_prot.c
        stack/source/security/protocols/sec_prot_certs.c
        stack/source/security/protocols/sec_prot_keys.c
        stack/source/security/protocols/sec_prot_lib.c
        stack/source/security/protocols/tls_sec_prot/tls_sec_prot.c
        stack/source/security/protocols/tls_sec_prot/tls_sec_prot_lib.c
        stack/source/service_libs/blacklist/blacklist.c
        stack/source/service_libs/etx/etx.c
        stack/source/service_libs/fnv_hash/fnv_hash.c
        stack/source/service_libs/hmac/hmac_md.c
        stack/source/service_libs/ieee_802_11/ieee_802_11.c
        stack/source/service_libs/mac_neighbor_table/mac_neighbor_table.c
        stack/source/service_libs/nist_aes_kw/nist_aes_kw.c
        stack/source/service_libs/random_early_detection/random_early_detection.c
    )
    target_include_directories(wsnode PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        stack/source/
        stack/
    )
    target_compile_options(wsnode PRIVATE -include stack/source/configs/cfg_ws_router.h)
    # target_compile_definitions(wsnode PRIVATE EXTRA_DEBUG_INFO)
    target_link_libraries(wsnode PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
    if(BACKTRACE_FOUND)
        target_compile_definitions(wsnode PRIVATE HAVE_BACKTRACE)
        target_sources(wsnode PRIVATE common/backtrace_show.c)
        target_link_libraries(wsnode PRIVATE backtrace)
    endif()
    if(LIBDL_FOUND)
        target_compile_definitions(wsnode PRIVATE HAVE_LIBDL)
        target_link_libraries(wsnode PRIVATE ${CMAKE_DL_LIBS})
    endif()
    install(TARGETS wsnode RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(wshwsim
        version.c
        common/crc.c
        common/bus_uart.c
        common/events_scheduler.c
        common/log.c
        common/bits.c
        common/endian.c
        common/rand.c
        common/iobuf.c
        common/slist.c
        common/spinel_buffer.c
        tools/hwsim/timer_sys_stub.c
        tools/hwsim/sl_wsrcp.c
        tools/hwsim/sl_wsrcp_mac.c
        tools/hwsim/sl_rf_driver.c
        tools/hwsim/hal_fhss_timer.c
        tools/hwsim/mac/rf_driver_storage.c
        tools/hwsim/mac/ieee802154/mac_cca_threshold.c
        tools/hwsim/mac/ieee802154/mac_fhss_callbacks.c
        tools/hwsim/mac/ieee802154/mac_filter.c
        tools/hwsim/mac/ieee802154/mac_header_helper_functions.c
        tools/hwsim/mac/ieee802154/mac_indirect_data.c
        tools/hwsim/mac/ieee802154/mac_mcps_sap.c
        tools/hwsim/mac/ieee802154/mac_mlme.c
        tools/hwsim/mac/ieee802154/mac_pd_sap.c
        tools/hwsim/mac/ieee802154/mac_security_mib.c
        tools/hwsim/mac/ieee802154/mac_timer.c
        tools/hwsim/mac/ieee802154/sw_mac.c
        tools/hwsim/ccm/ccm_security.c
        tools/hwsim/ccm/mbedOS/aes_mbedtls_adapter.c
        tools/hwsim/fhss/channel_functions.c
        tools/hwsim/fhss/fhss_common.c
        tools/hwsim/fhss/fhss_configuration_interface.c
        tools/hwsim/fhss/fhss_statistics.c
        tools/hwsim/fhss/fhss_ws.c
        tools/hwsim/os_timer.c
        # Excluded app_wshwsim/fhss/fhss_test_api.c
    )
    target_include_directories(wshwsim PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        tools/hwsim/
        stack/
    )
    # target_compile_definitions(wshwsim PRIVATE FHSS_CHANNEL_DEBUG)
    # target_compile_definitions(wshwsim PRIVATE TIMING_TOOL_TRACES)
    # target_compile_definitions(wshwsim PRIVATE EXTRA_DEBUG_INFO)
    target_link_libraries(wshwsim PRIVATE MbedTLS::mbedtls)
    target_link_libraries(wshwsim PRIVATE util)
    if(LIBPCAP_FOUND)
        target_compile_definitions(wshwsim PRIVATE HAVE_LIBPCAP)
        target_link_libraries(wshwsim PRIVATE PkgConfig::LIBPCAP)
    endif()
    if(BACKTRACE_FOUND)
        target_compile_definitions(wshwsim PRIVATE HAVE_BACKTRACE)
        target_sources(wshwsim PRIVATE common/backtrace_show.c)
        target_link_libraries(wshwsim PRIVATE backtrace)
    endif()
    if(LIBDL_FOUND)
        target_compile_definitions(wshwsim PRIVATE HAVE_LIBDL)
        target_link_libraries(wshwsim PRIVATE ${CMAKE_DL_LIBS})
    endif()
    install(TARGETS wshwsim RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(wssimserver
        common/log.c
        common/bits.c
        tools/simserver/wssimserver.c)
    target_include_directories(wssimserver PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    install(TARGETS wssimserver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(wsbrd-fuzz
        tools/fuzz/wsbrd_fuzz.c
        tools/fuzz/commandline.c
        tools/fuzz/interfaces.c
        tools/fuzz/capture.c
        tools/fuzz/replay.c
        tools/fuzz/rand.c
        tools/fuzz/main.c
    )
    target_compile_options(wsbrd-fuzz PRIVATE -include stack/source/configs/cfg_ws_border_router.h)
    target_include_directories(wsbrd-fuzz PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        stack/
        stack/source/
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
        -Wl,--wrap=tun_addr_get_global_unicast
        -Wl,--wrap=tun_addr_get_link_local
        -Wl,--wrap=wsbr_common_timer_init
        -Wl,--wrap=read
        -Wl,--wrap=write
        -Wl,--wrap=recv
        -Wl,--wrap=recvfrom
        -Wl,--wrap=socket
        -Wl,--wrap=setsockopt
        -Wl,--wrap=bind
        -Wl,--wrap=sendto
        -Wl,--wrap=sendmsg
        -Wl,--wrap=getrandom
        -Wl,--wrap=time
    )
    install(TARGETS wsbrd-fuzz RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(wshwping
        tools/hwping/wshwping.c
        common/bits.c
        common/log.c
        common/crc.c
        common/bus_uart.c
        common/spinel_buffer.c
        common/named_values.c
        common/iobuf.c
        common/endian.c
    )
    target_include_directories(wshwping PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        stack/source/
        stack/
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
            tools/simulation/rand.cpp
            tools/simulation/time.cpp
            tools/simulation/uart.cpp
            tools/fuzz/capture.c
            tools/fuzz/commandline.c
            tools/fuzz/interfaces.c
            tools/fuzz/rand.c
            tools/fuzz/wsbrd_fuzz.c
        )
        target_include_directories(wsbrd-ns3 PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            stack/
            ${NS3_INCLUDE_DIRECTORIES}
        )
        target_link_libraries(wsbrd-ns3 libwsbrd)
        target_link_libraries(wsbrd-ns3 Threads::Threads)
        target_link_options(wsbrd-ns3 PRIVATE
            -Wl,--wrap=uart_open
            -Wl,--wrap=write
            -Wl,--wrap=getrandom
            -Wl,--wrap=wsbr_common_timer_init
            -Wl,--wrap=wsbr_common_timer_process
            -Wl,--wrap=clock_gettime
            -Wl,--wrap=signal
            -Wl,--wrap=exit
            -Wl,--wrap=__tr_printf
            -Wl,--wrap=getrandom
            -Wl,--wrap=time
        )
        install(TARGETS wsbrd-ns3 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
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
# systemd does not document /usr/local/lib/systemd/system, but it seems to work
install(FILES misc/wisun-borderrouter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
# We try to avoid PATH hardcoding, but dbus does not watch
# /usr/local/share/dbus-1/system.d
install(FILES misc/com.silabs.Wisun.BorderRouter.conf
    DESTINATION /etc/dbus-1/system.d)
# FIXME: use ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/wsbrd and report this value in
# the code
install(DIRECTORY DESTINATION /var/lib/wsbrd
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ)
install(CODE "execute_process(COMMAND useradd --system --shell /sbin/nologin --home-dir /var/lib/wsbrd wsbrd)")
install(CODE "execute_process(COMMAND chown -R wsbrd:wsbrd /var/lib/wsbrd)")
