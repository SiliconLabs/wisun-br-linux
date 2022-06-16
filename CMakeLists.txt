cmake_minimum_required(VERSION  3.16.3)
project(wsbrd)
set(COMPILE_SIMULATION_TOOLS OFF CACHE BOOL "Keep unset if you don't consider to develop new features")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GNUInstallDirs)

include(CheckCCompilerFlag)
check_c_compiler_flag(-Wall                  CC_HAVE_WALL)
check_c_compiler_flag(-Wno-stringop-overread CC_HAVE_WNO_STRINGOP_OVERREAD)
check_c_compiler_flag(-Wno-stringop-overflow CC_HAVE_WNO_STRINGOP_OVERFLOW)
check_c_compiler_flag(-funwind-tables        CC_HAVE_UNWIND_TABLES)
check_c_compiler_flag(-rdynamic              CC_HAVE_RDYNAMIC)

include(CheckIncludeFile)
# Depending of the distribution backtrace.h may be packaged with gcc. Else,
# the libbacktrace project provides a fully compatible library.
check_include_file(backtrace.h BACKTRACE_FOUND)

find_package(Rust)
find_package(Cargo)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Syntax "MbedTLS 2.18...<4" does not work :(
find_package(MbedTLS REQUIRED)
mark_as_advanced(MbedTLS_DIR)

find_package(PkgConfig REQUIRED)
# Note that old libpcap releases didn't provide pkg-config file and are not
# detected by the line below. The user have to compile without support for
# libpcap or manually defines the flags.
pkg_check_modules(LIBPCAP              IMPORTED_TARGET libpcap)
pkg_check_modules(LIBSYSTEMD           IMPORTED_TARGET libsystemd)
pkg_check_modules(LIBNL_ROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)

include(CheckSymbolExists)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(dladdr dlfcn.h LIBDL_FOUND)

# Greatly improve warning messages. There is no reason to not enable that.
if(CC_HAVE_WALL)
    add_compile_options(-Wall)
endif()

# ... but it generate two irrelevant warnings
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
    COMMAND ${CMAKE_SOURCE_DIR}/version.sh ${CMAKE_SOURCE_DIR} version.c)

add_library(libwsbrd STATIC
    version.c
    app_wsbrd/wsbr.c
    app_wsbrd/wsbr_mac.c
    app_wsbrd/wsbr_fhss_mac.c
    app_wsbrd/wsbr_fhss_net.c
    app_wsbrd/timers.c
    app_wsbrd/tun.c
    app_wsbrd/commandline.c
    app_wsbrd/commandline_values.c
    app_wsbrd/os_whiteboard.c
    app_wsbrd/mbedtls_config_check.c
    common/crc.c
    common/bus_uart.c
    common/hal_interrupt.c
    common/os_scheduler.c
    common/log.c
    common/bits.c
    common/rand.c
    common/named_values.c
    common/parsers.c
    common/slist.c
    common/spinel_buffer.c
    common/trickle.c
    common/ws_regdb.c
    stack/source/6lowpan/adaptation_interface.c
    stack/source/6lowpan/bootstraps/network_lib.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
    stack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
    stack/source/6lowpan/fragmentation/cipv6_fragmenter.c
    stack/source/6lowpan/iphc_decode/6lowpan_iphc.c
    stack/source/6lowpan/iphc_decode/iphc_compress.c
    stack/source/6lowpan/iphc_decode/iphc_decompress.c
    stack/source/6lowpan/iphc_decode/lowpan_context.c
    stack/source/6lowpan/mac/mac_helper.c
    stack/source/6lowpan/mac/mac_ie_lib.c
    stack/source/6lowpan/mac/mac_response_handler.c
    # Excluded stack/source/6lowpan/Mesh
    stack/source/6lowpan/nd/nd_router_object.c
    # Excluded stack/source/6lowpan/Thread
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
    stack/source/6lowpan/ws/ws_llc_data_service.c
    stack/source/6lowpan/ws/ws_management_api.c
    stack/source/6lowpan/ws/ws_mpx_header.c
    stack/source/6lowpan/ws/ws_neighbor_class.c
    stack/source/6lowpan/ws/ws_pae_auth.c
    stack/source/6lowpan/ws/ws_pae_controller.c
    stack/source/6lowpan/ws/ws_pae_key_storage.c
    stack/source/6lowpan/ws/ws_pae_lib.c
    stack/source/6lowpan/ws/ws_pae_nvm_store.c
    stack/source/6lowpan/ws/ws_pae_nvm_data.c
    stack/source/6lowpan/ws/ws_pae_supp.c
    stack/source/6lowpan/ws/ws_pae_time.c
    stack/source/6lowpan/ws/ws_pae_timers.c
    stack/source/6lowpan/ws/ws_regulation.c
    stack/source/6lowpan/ws/ws_stats.c
    stack/source/6lowpan/ws/ws_test_api.c
    stack/source/common_protocols/icmpv6.c
    stack/source/common_protocols/icmpv6_prefix.c
    stack/source/common_protocols/icmpv6_radv.c
    stack/source/common_protocols/ipv6.c
    stack/source/common_protocols/ipv6_flow.c
    stack/source/common_protocols/ipv6_fragmentation.c
    stack/source/common_protocols/ipv6_resolution.c
    stack/source/common_protocols/mld.c
    stack/source/common_protocols/udp.c
    stack/source/core/ns_address_internal.c
    stack/source/core/ns_buffer.c
    stack/source/core/ns_socket.c
    stack/source/core/sockbuf.c
    stack/source/dhcpv6_client/dhcpv6_client_service.c
    stack/source/dhcpv6_server/dhcpv6_server_service.c
    stack/source/ipv6_stack/ipv6_routing_table.c
    stack/source/ipv6_stack/protocol_ipv6.c
    stack/source/libdhcpv6/dhcp_service_api.c
    stack/source/libdhcpv6/libdhcpv6.c
    stack/source/libdhcpv6/libdhcpv6_server.c
    stack/source/libdhcpv6/libdhcpv6_vendordata.c
    stack/source/net_lib/net_short_address_extension.c
    stack/source/net_lib/net_dns.c
    stack/source/net_lib/multicast_api.c
    stack/source/net_lib/net_6lowpan_parameter_api.c
    stack/source/net_lib/net_rpl.c
    stack/source/net_lib/ns_net.c
    stack/source/net_lib/socket_api.c
    stack/source/net_lib/net_ipv6.c
    stack/source/mac/rf_driver_storage.c
    stack/source/mac/ethernet/ethernet_mac_api.c
    # Excluded stack/source/mac/ieee802154
    stack/source/mpl/mpl.c
    stack/source/nwk_interface/protocol_core.c
    stack/source/nwk_interface/protocol_stats.c
    stack/source/nwk_interface/protocol_timer.c
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
    stack/source/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    stack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    stack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    stack/source/security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
    stack/source/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    stack/source/security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
    stack/source/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
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
    stack/source/service_libs/nd_proxy/nd_proxy.c
    stack/source/service_libs/nist_aes_kw/nist_aes_kw.c
    stack/source/service_libs/random_early_detection/random_early_detection.c
    stack/source/service_libs/utils/isqrt.c
    stack/source/service_libs/utils/ns_file_system.c
    stack/source/service_libs/utils/ns_time.c
    # Excluded stack/source/service_libs/whiteboard/whiteboard.c
    stack-scheduler/source/event.c
    stack-scheduler/source/timer_sys.c
    stack-services/common_functions.c
    stack-services/ip6string.c
    stack-services/ns_list.c
    stack-services/ns_trace.c
    # Excluded stack-services/nvmHelper
)
target_include_directories(libwsbrd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    stack/source/
    stack-scheduler/
    stack/
)
target_compile_definitions(libwsbrd PRIVATE NSCONFIG=ws_border_router)
target_compile_options(libwsbrd PRIVATE -fPIC)
# target_compile_definitions(libwsbrd PRIVATE EXTRA_DEBUG_INFO)
target_link_libraries(libwsbrd PRIVATE Threads::Threads)
target_link_libraries(libwsbrd PRIVATE PkgConfig::LIBNL_ROUTE)
target_link_libraries(libwsbrd PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
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
set_target_properties(libwsbrd PROPERTIES OUTPUT_NAME wsbrd)

add_executable(wsbrd app_wsbrd/wsbrd.c)
add_dependencies(wsbrd libwsbrd)
target_link_libraries(wsbrd libwsbrd)
install(TARGETS wsbrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# FIXME: use ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/wsbrd and report this value in
# the code
install(DIRECTORY DESTINATION /var/lib/wsbrd)
install(FILES misc/com.silabs.Wisun.BorderRouter.service
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/dbus-1/system-services)
# systemd does not document /usr/local/lib/systemd/system, but it seems to work
install(FILES misc/wisun-borderrouter.service
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
# We try to avoid PATH hardcoding, but dbus does not watch
# /usr/local/share/dbus-1/system.d
install(FILES misc/com.silabs.Wisun.BorderRouter.conf
        DESTINATION /etc/dbus-1/system.d)
install(FILES CHANGES.md README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES examples/wsbrd.conf examples/br_cert.pem examples/br_key.pem
              examples/ca_cert.pem examples/node_cert.pem examples/node_key.pem
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)

add_executable(wsbrd-fuzz
    app_wsbrd_fuzz/wsbrd_fuzz.c
    app_wsbrd_fuzz/commandline.c
    app_wsbrd_fuzz/capture.c
    app_wsbrd_fuzz/rand.c
)
target_include_directories(wsbrd-fuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    stack/
)
add_dependencies(wsbrd-fuzz libwsbrd)
target_link_libraries(wsbrd-fuzz libwsbrd)
if(BACKTRACE_FOUND)
    target_compile_definitions(wsbrd-fuzz PRIVATE HAVE_BACKTRACE)
endif()
target_link_options(wsbrd-fuzz PRIVATE
    -Wl,--wrap=print_help_br
    -Wl,--wrap=uart_open
    -Wl,--wrap=uart_rx
    -Wl,--wrap=read
    -Wl,--wrap=getrandom
    -Wl,--wrap=time
)

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
                                       --manifest-path=${CMAKE_CURRENT_SOURCE_DIR}/app_wsbrd_cli/Cargo.toml
        COMMAND ${CMAKE_COMMAND} -E copy ${RUST_TARGET_DIR}/wsbrd_cli wsbrd_cli
        DEPENDS app_wsbrd_cli/Cargo.toml app_wsbrd_cli/wsbrd_cli.rs app_wsbrd_cli/wsbrddbusapi.rs
        USES_TERMINAL
    )
    set_target_properties(cargo-wsbrd_cli PROPERTIES ADDITIONAL_CLEAN_FILES cargo)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wsbrd_cli DESTINATION ${CMAKE_INSTALL_BINDIR})

endif()

if(COMPILE_SIMULATION_TOOLS)

    add_executable(wsnode
        version.c
        app_wsbrd/wsrouter.c
        app_wsbrd/wsbr_mac.c
        app_wsbrd/wsbr_fhss_mac.c
        app_wsbrd/wsbr_fhss_net.c
        app_wsbrd/timers.c
        app_wsbrd/commandline.c
        app_wsbrd/commandline_values.c
        common/crc.c
        common/bus_uart.c
        common/hal_interrupt.c
        common/os_scheduler.c
        common/log.c
        common/bits.c
        common/rand.c
        common/named_values.c
        common/parsers.c
        common/slist.c
        common/spinel_buffer.c
        common/trickle.c
        common/ws_regdb.c
        stack/source/6lowpan/adaptation_interface.c
        stack/source/6lowpan/bootstraps/network_lib.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
        stack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
        stack/source/6lowpan/fragmentation/cipv6_fragmenter.c
        stack/source/6lowpan/iphc_decode/6lowpan_iphc.c
        stack/source/6lowpan/iphc_decode/iphc_compress.c
        stack/source/6lowpan/iphc_decode/iphc_decompress.c
        stack/source/6lowpan/iphc_decode/lowpan_context.c
        stack/source/6lowpan/mac/mac_helper.c
        stack/source/6lowpan/mac/mac_ie_lib.c
        stack/source/6lowpan/mac/mac_response_handler.c
        # Excluded stack/source/6lowpan/Mesh
        stack/source/6lowpan/nd/nd_router_object.c
        # Excluded stack/source/6lowpan/Thread
        stack/source/6lowpan/ws/ws_bootstrap.c
        stack/source/6lowpan/ws/ws_bootstrap_ffn.c
        stack/source/6lowpan/ws/ws_cfg_settings.c
        stack/source/6lowpan/ws/ws_common.c
        stack/source/6lowpan/ws/ws_eapol_auth_relay.c
        stack/source/6lowpan/ws/ws_eapol_pdu.c
        stack/source/6lowpan/ws/ws_eapol_relay.c
        stack/source/6lowpan/ws/ws_eapol_relay_lib.c
        stack/source/6lowpan/ws/ws_ie_lib.c
        stack/source/6lowpan/ws/ws_llc_data_service.c
        stack/source/6lowpan/ws/ws_management_api.c
        stack/source/6lowpan/ws/ws_mpx_header.c
        stack/source/6lowpan/ws/ws_neighbor_class.c
        # stack/source/6lowpan/ws/ws_pae_auth.c
        stack/source/6lowpan/ws/ws_pae_controller.c
        stack/source/6lowpan/ws/ws_pae_key_storage.c
        stack/source/6lowpan/ws/ws_pae_lib.c
        stack/source/6lowpan/ws/ws_pae_nvm_store.c
        stack/source/6lowpan/ws/ws_pae_nvm_data.c
        stack/source/6lowpan/ws/ws_pae_supp.c
        stack/source/6lowpan/ws/ws_pae_time.c
        stack/source/6lowpan/ws/ws_pae_timers.c
        stack/source/6lowpan/ws/ws_regulation.c
        stack/source/6lowpan/ws/ws_stats.c
        stack/source/6lowpan/ws/ws_test_api.c
        stack/source/common_protocols/icmpv6.c
        stack/source/common_protocols/icmpv6_prefix.c
        stack/source/common_protocols/icmpv6_radv.c
        stack/source/common_protocols/ipv6.c
        stack/source/common_protocols/ipv6_flow.c
        stack/source/common_protocols/ipv6_fragmentation.c
        stack/source/common_protocols/ipv6_resolution.c
        stack/source/common_protocols/mld.c
        stack/source/common_protocols/udp.c
        stack/source/core/ns_address_internal.c
        stack/source/core/ns_buffer.c
        stack/source/core/ns_socket.c
        stack/source/core/sockbuf.c
        stack/source/dhcpv6_client/dhcpv6_client_service.c
        stack/source/ipv6_stack/ipv6_routing_table.c
        stack/source/ipv6_stack/protocol_ipv6.c
        stack/source/libdhcpv6/dhcp_service_api.c
        stack/source/libdhcpv6/libdhcpv6.c
        stack/source/libdhcpv6/libdhcpv6_vendordata.c
        stack/source/net_lib/net_short_address_extension.c
        stack/source/net_lib/net_dns.c
        stack/source/net_lib/multicast_api.c
        stack/source/net_lib/net_6lowpan_parameter_api.c
        stack/source/net_lib/net_rpl.c
        stack/source/net_lib/ns_net.c
        stack/source/net_lib/socket_api.c
        stack/source/net_lib/net_ipv6.c
        stack/source/mac/rf_driver_storage.c
        stack/source/mac/ethernet/ethernet_mac_api.c
        # Excluded stack/source/mac/ieee802154
        stack/source/mpl/mpl.c
        stack/source/nwk_interface/protocol_core.c
        stack/source/nwk_interface/protocol_stats.c
        stack/source/nwk_interface/protocol_timer.c
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
        # stack/source/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
        stack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
        stack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
        stack/source/security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
        # stack/source/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
        stack/source/security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
        # stack/source/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
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
        stack/source/service_libs/nd_proxy/nd_proxy.c
        stack/source/service_libs/nist_aes_kw/nist_aes_kw.c
        stack/source/service_libs/random_early_detection/random_early_detection.c
        stack/source/service_libs/utils/isqrt.c
        stack/source/service_libs/utils/ns_file_system.c
        stack/source/service_libs/utils/ns_time.c
        # Excluded stack/source/service_libs/whiteboard/whiteboard.c
        stack-scheduler/source/event.c
        stack-scheduler/source/timer_sys.c
        stack-services/common_functions.c
        stack-services/ip6string.c
        stack-services/ns_list.c
        stack-services/ns_trace.c
    )
    target_include_directories(wsnode PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        stack/source/
        stack-scheduler/
        stack/
    )
    target_compile_definitions(wsnode PRIVATE NSCONFIG=ws_router)
    # target_compile_definitions(wsnode PRIVATE EXTRA_DEBUG_INFO)
    target_link_libraries(wsnode PRIVATE Threads::Threads)
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
        common/hal_interrupt.c
        common/os_scheduler.c
        common/log.c
        common/bits.c
        common/rand.c
        common/slist.c
        common/spinel_buffer.c
        stack-services/common_functions.c
        stack-services/ip6string.c
        stack-services/ns_list.c
        stack-services/ns_trace.c
        stack-scheduler/source/event.c
        app_wshwsim/timer_sys_stub.c
        app_wshwsim/sl_wsrcp.c
        app_wshwsim/sl_wsrcp_mac.c
        app_wshwsim/sl_rf_driver.c
        app_wshwsim/hal_fhss_timer.c
        app_wshwsim/mac/rf_driver_storage.c
        app_wshwsim/mac/ieee802154/mac_cca_threshold.c
        app_wshwsim/mac/ieee802154/mac_fhss_callbacks.c
        app_wshwsim/mac/ieee802154/mac_filter.c
        app_wshwsim/mac/ieee802154/mac_header_helper_functions.c
        app_wshwsim/mac/ieee802154/mac_indirect_data.c
        app_wshwsim/mac/ieee802154/mac_mcps_sap.c
        app_wshwsim/mac/ieee802154/mac_mlme.c
        app_wshwsim/mac/ieee802154/mac_pd_sap.c
        app_wshwsim/mac/ieee802154/mac_security_mib.c
        app_wshwsim/mac/ieee802154/mac_timer.c
        app_wshwsim/mac/ieee802154/sw_mac.c
        app_wshwsim/ccm/ccm_security.c
        app_wshwsim/ccm/mbedOS/aes_mbedtls_adapter.c
        app_wshwsim/fhss/channel_functions.c
        app_wshwsim/fhss/channel_list.c
        app_wshwsim/fhss/fhss_common.c
        app_wshwsim/fhss/fhss_configuration_interface.c
        app_wshwsim/fhss/fhss_statistics.c
        app_wshwsim/fhss/fhss_ws.c
        app_wshwsim/os_timer.c
        # Excluded app_wshwsim/fhss/fhss_test_api.c
    )
    target_include_directories(wshwsim PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        app_wshwsim/
        stack-scheduler/
        stack/
    )
    # target_compile_definitions(wshwsim PRIVATE FHSS_CHANNEL_DEBUG)
    # target_compile_definitions(wshwsim PRIVATE TIMING_TOOL_TRACES)
    # target_compile_definitions(wshwsim PRIVATE EXTRA_DEBUG_INFO)
    target_link_libraries(wshwsim PRIVATE Threads::Threads)
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
        app_wssimserver/wssimserver.c)
    target_include_directories(wssimserver PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    install(TARGETS wssimserver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

endif()
