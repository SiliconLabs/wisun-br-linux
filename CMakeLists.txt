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
check_include_file(backtrace.h BACKTRACE_FOUND)

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

add_executable(wsbrd
    version.c
    app_wsbrd/wsbr.c
    app_wsbrd/wsbr_mac.c
    app_wsbrd/wsbr_fhss_mac.c
    app_wsbrd/wsbr_fhss_net.c
    app_wsbrd/tun.c
    app_wsbrd/named_values.c
    app_wsbrd/commandline.c
    app_wsbrd/os_whiteboard.c
    app_wsbrd/mbedtls_config_check.c
    common/bus_uart.c
    common/hal_interrupt.c
    common/os_timer.c
    common/os_scheduler.c
    common/log.c
    common/rand.c
    common/slist.c
    common/spinel_buffer.c
    nanostack/source/6lowpan/adaptation_interface.c
    nanostack/source/6lowpan/bootstraps/network_lib.c
    nanostack/source/6lowpan/bootstraps/protocol_6lowpan.c
    nanostack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
    nanostack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
    nanostack/source/6lowpan/fragmentation/cipv6_fragmenter.c
    nanostack/source/6lowpan/iphc_decode/6lowpan_iphc.c
    nanostack/source/6lowpan/iphc_decode/iphc_compress.c
    nanostack/source/6lowpan/iphc_decode/iphc_decompress.c
    nanostack/source/6lowpan/iphc_decode/lowpan_context.c
    nanostack/source/6lowpan/mac/mac_helper.c
    nanostack/source/6lowpan/mac/mac_ie_lib.c
    nanostack/source/6lowpan/mac/mac_response_handler.c
    # Excluded nanostack/source/6lowpan/Mesh
    nanostack/source/6lowpan/nd/nd_router_object.c
    # Excluded nanostack/source/6lowpan/Thread
    nanostack/source/6lowpan/ws/ws_bbr_api.c
    nanostack/source/6lowpan/ws/ws_bootstrap.c
    nanostack/source/6lowpan/ws/ws_bootstrap_6lbr.c
    nanostack/source/6lowpan/ws/ws_bootstrap_ffn.c
    nanostack/source/6lowpan/ws/ws_bootstrap_lfn.c
    nanostack/source/6lowpan/ws/ws_cfg_settings.c
    nanostack/source/6lowpan/ws/ws_common.c
    nanostack/source/6lowpan/ws/ws_eapol_auth_relay.c
    nanostack/source/6lowpan/ws/ws_eapol_pdu.c
    nanostack/source/6lowpan/ws/ws_eapol_relay.c
    nanostack/source/6lowpan/ws/ws_eapol_relay_lib.c
    nanostack/source/6lowpan/ws/ws_ie_lib.c
    nanostack/source/6lowpan/ws/ws_llc_data_service.c
    nanostack/source/6lowpan/ws/ws_management_api.c
    nanostack/source/6lowpan/ws/ws_mpx_header.c
    nanostack/source/6lowpan/ws/ws_neighbor_class.c
    nanostack/source/6lowpan/ws/ws_pae_auth.c
    nanostack/source/6lowpan/ws/ws_pae_controller.c
    nanostack/source/6lowpan/ws/ws_pae_key_storage.c
    nanostack/source/6lowpan/ws/ws_pae_lib.c
    nanostack/source/6lowpan/ws/ws_pae_nvm_store.c
    nanostack/source/6lowpan/ws/ws_pae_nvm_data.c
    nanostack/source/6lowpan/ws/ws_pae_supp.c
    nanostack/source/6lowpan/ws/ws_pae_time.c
    nanostack/source/6lowpan/ws/ws_pae_timers.c
    nanostack/source/6lowpan/ws/ws_phy.c
    nanostack/source/6lowpan/ws/ws_regulation_arib.c
    nanostack/source/6lowpan/ws/ws_regulation_none.c
    nanostack/source/6lowpan/ws/ws_regulation.c
    nanostack/source/6lowpan/ws/ws_stats.c
    nanostack/source/6lowpan/ws/ws_test_api.c
    nanostack/source/common_protocols/icmpv6.c
    nanostack/source/common_protocols/icmpv6_prefix.c
    nanostack/source/common_protocols/icmpv6_radv.c
    nanostack/source/common_protocols/ipv6.c
    nanostack/source/common_protocols/ipv6_flow.c
    nanostack/source/common_protocols/ipv6_fragmentation.c
    nanostack/source/common_protocols/ipv6_resolution.c
    nanostack/source/common_protocols/mld.c
    nanostack/source/common_protocols/udp.c
    nanostack/source/core/ns_address_internal.c
    nanostack/source/core/ns_buffer.c
    nanostack/source/core/ns_socket.c
    nanostack/source/core/sockbuf.c
    nanostack/source/dhcpv6_client/dhcpv6_client_service.c
    nanostack/source/dhcpv6_server/dhcpv6_server_service.c
    nanostack/source/ipv6_stack/ipv6_routing_table.c
    nanostack/source/ipv6_stack/protocol_ipv6.c
    nanostack/source/libdhcpv6/dhcp_service_api.c
    nanostack/source/libdhcpv6/libdhcpv6.c
    nanostack/source/libdhcpv6/libdhcpv6_server.c
    nanostack/source/libdhcpv6/libdhcpv6_vendordata.c
    nanostack/source/net_lib/net_short_address_extension.c
    nanostack/source/net_lib/net_dns.c
    nanostack/source/net_lib/multicast_api.c
    nanostack/source/net_lib/net_6lowpan_parameter_api.c
    nanostack/source/net_lib/net_rpl.c
    nanostack/source/net_lib/ns_net.c
    nanostack/source/net_lib/socket_api.c
    nanostack/source/net_lib/net_ipv6.c
    nanostack/source/mac/rf_driver_storage.c
    nanostack/source/mac/ethernet/ethernet_mac_api.c
    # Excluded nanostack/source/mac/ieee802154
    nanostack/source/mpl/mpl.c
    nanostack/source/nwk_interface/protocol_core.c
    nanostack/source/nwk_interface/protocol_stats.c
    nanostack/source/nwk_interface/protocol_timer.c
    nanostack/source/rpl/rpl_control.c
    nanostack/source/rpl/rpl_mrhof.c
    nanostack/source/rpl/rpl_downward.c
    nanostack/source/rpl/rpl_data.c
    nanostack/source/rpl/rpl_objective.c
    nanostack/source/rpl/rpl_of0.c
    nanostack/source/rpl/rpl_policy.c
    nanostack/source/rpl/rpl_upward.c
    nanostack/source/security/eapol/eapol_helper.c
    nanostack/source/security/eapol/kde_helper.c
    nanostack/source/security/kmp/kmp_addr.c
    nanostack/source/security/kmp/kmp_api.c
    nanostack/source/security/kmp/kmp_eapol_pdu_if.c
    nanostack/source/security/kmp/kmp_socket_if.c
    nanostack/source/security/pana/pana_eap_header.c
    nanostack/source/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    nanostack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    nanostack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    nanostack/source/security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
    nanostack/source/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    nanostack/source/security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
    nanostack/source/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    nanostack/source/security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
    nanostack/source/security/protocols/key_sec_prot/key_sec_prot.c
    nanostack/source/security/protocols/msg_sec_prot/msg_sec_prot.c
    nanostack/source/security/protocols/radius_sec_prot/avp_helper.c
    nanostack/source/security/protocols/radius_sec_prot/radius_client_sec_prot.c
    nanostack/source/security/protocols/sec_prot_certs.c
    nanostack/source/security/protocols/sec_prot_keys.c
    nanostack/source/security/protocols/sec_prot_lib.c
    nanostack/source/security/protocols/tls_sec_prot/tls_sec_prot.c
    nanostack/source/security/protocols/tls_sec_prot/tls_sec_prot_lib.c
    nanostack/source/service_libs/blacklist/blacklist.c
    nanostack/source/service_libs/etx/etx.c
    nanostack/source/service_libs/fnv_hash/fnv_hash.c
    nanostack/source/service_libs/hmac/hmac_md.c
    nanostack/source/service_libs/ieee_802_11/ieee_802_11.c
    nanostack/source/service_libs/mac_neighbor_table/mac_neighbor_table.c
    nanostack/source/service_libs/nd_proxy/nd_proxy.c
    nanostack/source/service_libs/nist_aes_kw/nist_aes_kw.c
    nanostack/source/service_libs/random_early_detection/random_early_detection.c
    nanostack/source/service_libs/sha256/ns_sha256.c
    nanostack/source/service_libs/sha256/shalib.c
    nanostack/source/service_libs/trickle/trickle.c
    nanostack/source/service_libs/utils/isqrt.c
    nanostack/source/service_libs/utils/ns_file_system.c
    nanostack/source/service_libs/utils/ns_time.c
    # Excluded nanostack/source/service_libs/whiteboard/whiteboard.c
    nanostack-event-loop/source/event.c
    nanostack-event-loop/source/system_timer.c
    mbed-client-libservice/source/libBits/common_functions.c
    mbed-client-libservice/source/libip6string/ip6tos.c
    mbed-client-libservice/source/libip6string/stoip6.c
    mbed-client-libservice/source/libList/ns_list.c
    mbed-client-libservice/source/libtrace/ns_trace.c
    # Excluded mbed-client-libservice/source/nvmHelper
)
target_include_directories(wsbrd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    nanostack/source/
    mbed-trace/
    mbed-client-libservice/
    nanostack-event-loop/
    nanostack/
)
target_compile_definitions(wsbrd PRIVATE NSCONFIG=ws_border_router)
# target_compile_definitions(wsbrd PRIVATE EXTRA_DEBUG_INFO)
target_link_libraries(wsbrd PRIVATE Threads::Threads)
target_link_libraries(wsbrd PRIVATE PkgConfig::LIBNL_ROUTE)
target_link_libraries(wsbrd PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
if(LIBSYSTEMD_FOUND)
    target_compile_definitions(wsbrd PRIVATE HAVE_LIBSYSTEMD)
    target_sources(wsbrd PRIVATE app_wsbrd/dbus.c)
    target_link_libraries(wsbrd PRIVATE PkgConfig::LIBSYSTEMD)
endif()
if(BACKTRACE_FOUND)
    target_compile_definitions(wsbrd PRIVATE HAVE_BACKTRACE)
    target_sources(wsbrd PRIVATE common/backtrace_show.c)
    target_link_libraries(wsbrd PRIVATE backtrace)
endif()
if(LIBDL_FOUND)
    target_compile_definitions(wsbrd PRIVATE HAVE_LIBDL)
    target_link_libraries(wsbrd PRIVATE ${CMAKE_DL_LIBS})
endif()
install(TARGETS wsbrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# FIXME: use ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/wsbrd and report this value in
# the code
install(DIRECTORY DESTINATION /var/lib/wsbrd)
install(FILES misc/com.silabs.Wisun.BorderRouter.service
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/dbus-1/system-services)
install(FILES misc/wisun-borderouter.service
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
# We try to avoid PATH hardcoding, but dbus does not watch
# /usr/local/share/dbus-1/system.d
install(FILES misc/com.silabs.Wisun.BorderRouter.conf
        DESTINATION /etc/dbus-1/system.d)
install(FILES CHANGES.md README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES examples/wsbrd.conf examples/br_cert.pem examples/br_key.pem
              examples/ca_cert.pem examples/node_cert.pem examples/node_key.pem
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)

if(COMPILE_SIMULATION_TOOLS)

    add_executable(wsnode
        version.c
        app_wsbrd/wsrouter.c
        app_wsbrd/wsbr_mac.c
        app_wsbrd/wsbr_fhss_mac.c
        app_wsbrd/wsbr_fhss_net.c
        app_wsbrd/commandline.c
        app_wsbrd/named_values.c
        common/bus_uart.c
        common/hal_interrupt.c
        common/os_timer.c
        common/os_scheduler.c
        common/log.c
        common/rand.c
        common/slist.c
        common/spinel_buffer.c
        nanostack/source/6lowpan/adaptation_interface.c
        nanostack/source/6lowpan/bootstraps/network_lib.c
        nanostack/source/6lowpan/bootstraps/protocol_6lowpan.c
        nanostack/source/6lowpan/bootstraps/protocol_6lowpan_bootstrap.c
        nanostack/source/6lowpan/bootstraps/protocol_6lowpan_interface.c
        nanostack/source/6lowpan/fragmentation/cipv6_fragmenter.c
        nanostack/source/6lowpan/iphc_decode/6lowpan_iphc.c
        nanostack/source/6lowpan/iphc_decode/iphc_compress.c
        nanostack/source/6lowpan/iphc_decode/iphc_decompress.c
        nanostack/source/6lowpan/iphc_decode/lowpan_context.c
        nanostack/source/6lowpan/mac/mac_helper.c
        nanostack/source/6lowpan/mac/mac_ie_lib.c
        nanostack/source/6lowpan/mac/mac_response_handler.c
        # Excluded nanostack/source/6lowpan/Mesh
        nanostack/source/6lowpan/nd/nd_router_object.c
        # Excluded nanostack/source/6lowpan/Thread
        nanostack/source/6lowpan/ws/ws_bootstrap.c
        nanostack/source/6lowpan/ws/ws_bootstrap_ffn.c
        nanostack/source/6lowpan/ws/ws_bootstrap_lfn.c
        nanostack/source/6lowpan/ws/ws_cfg_settings.c
        nanostack/source/6lowpan/ws/ws_common.c
        nanostack/source/6lowpan/ws/ws_eapol_auth_relay.c
        nanostack/source/6lowpan/ws/ws_eapol_pdu.c
        nanostack/source/6lowpan/ws/ws_eapol_relay.c
        nanostack/source/6lowpan/ws/ws_eapol_relay_lib.c
        nanostack/source/6lowpan/ws/ws_ie_lib.c
        nanostack/source/6lowpan/ws/ws_llc_data_service.c
        nanostack/source/6lowpan/ws/ws_management_api.c
        nanostack/source/6lowpan/ws/ws_mpx_header.c
        nanostack/source/6lowpan/ws/ws_neighbor_class.c
        nanostack/source/6lowpan/ws/ws_pae_auth.c
        nanostack/source/6lowpan/ws/ws_pae_controller.c
        nanostack/source/6lowpan/ws/ws_pae_key_storage.c
        nanostack/source/6lowpan/ws/ws_pae_lib.c
        nanostack/source/6lowpan/ws/ws_pae_nvm_store.c
        nanostack/source/6lowpan/ws/ws_pae_nvm_data.c
        nanostack/source/6lowpan/ws/ws_pae_supp.c
        nanostack/source/6lowpan/ws/ws_pae_time.c
        nanostack/source/6lowpan/ws/ws_pae_timers.c
        nanostack/source/6lowpan/ws/ws_phy.c
        nanostack/source/6lowpan/ws/ws_regulation_arib.c
        nanostack/source/6lowpan/ws/ws_regulation_none.c
        nanostack/source/6lowpan/ws/ws_regulation.c
        nanostack/source/6lowpan/ws/ws_stats.c
        nanostack/source/6lowpan/ws/ws_test_api.c
        nanostack/source/common_protocols/icmpv6.c
        nanostack/source/common_protocols/icmpv6_prefix.c
        nanostack/source/common_protocols/icmpv6_radv.c
        nanostack/source/common_protocols/ipv6.c
        nanostack/source/common_protocols/ipv6_flow.c
        nanostack/source/common_protocols/ipv6_fragmentation.c
        nanostack/source/common_protocols/ipv6_resolution.c
        nanostack/source/common_protocols/mld.c
        nanostack/source/common_protocols/udp.c
        nanostack/source/core/ns_address_internal.c
        nanostack/source/core/ns_buffer.c
        nanostack/source/core/ns_socket.c
        nanostack/source/core/sockbuf.c
        nanostack/source/dhcpv6_client/dhcpv6_client_service.c
        nanostack/source/ipv6_stack/ipv6_routing_table.c
        nanostack/source/ipv6_stack/protocol_ipv6.c
        nanostack/source/libdhcpv6/dhcp_service_api.c
        nanostack/source/libdhcpv6/libdhcpv6.c
        nanostack/source/libdhcpv6/libdhcpv6_vendordata.c
        nanostack/source/net_lib/net_short_address_extension.c
        nanostack/source/net_lib/net_dns.c
        nanostack/source/net_lib/multicast_api.c
        nanostack/source/net_lib/net_6lowpan_parameter_api.c
        nanostack/source/net_lib/net_rpl.c
        nanostack/source/net_lib/ns_net.c
        nanostack/source/net_lib/socket_api.c
        nanostack/source/net_lib/net_ipv6.c
        nanostack/source/mac/rf_driver_storage.c
        nanostack/source/mac/ethernet/ethernet_mac_api.c
        # Excluded nanostack/source/mac/ieee802154
        nanostack/source/mpl/mpl.c
        nanostack/source/nwk_interface/protocol_core.c
        nanostack/source/nwk_interface/protocol_stats.c
        nanostack/source/nwk_interface/protocol_timer.c
        nanostack/source/rpl/rpl_control.c
        nanostack/source/rpl/rpl_mrhof.c
        nanostack/source/rpl/rpl_downward.c
        nanostack/source/rpl/rpl_data.c
        nanostack/source/rpl/rpl_objective.c
        nanostack/source/rpl/rpl_of0.c
        nanostack/source/rpl/rpl_policy.c
        nanostack/source/rpl/rpl_upward.c
        nanostack/source/security/eapol/eapol_helper.c
        nanostack/source/security/eapol/kde_helper.c
        nanostack/source/security/kmp/kmp_addr.c
        nanostack/source/security/kmp/kmp_api.c
        nanostack/source/security/kmp/kmp_eapol_pdu_if.c
        nanostack/source/security/kmp/kmp_socket_if.c
        nanostack/source/security/pana/pana_eap_header.c
        nanostack/source/security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
        nanostack/source/security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
        nanostack/source/security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
        nanostack/source/security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
        nanostack/source/security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
        nanostack/source/security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
        nanostack/source/security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
        nanostack/source/security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
        nanostack/source/security/protocols/key_sec_prot/key_sec_prot.c
        nanostack/source/security/protocols/msg_sec_prot/msg_sec_prot.c
        nanostack/source/security/protocols/radius_sec_prot/avp_helper.c
        nanostack/source/security/protocols/radius_sec_prot/radius_client_sec_prot.c
        nanostack/source/security/protocols/sec_prot_certs.c
        nanostack/source/security/protocols/sec_prot_keys.c
        nanostack/source/security/protocols/sec_prot_lib.c
        nanostack/source/security/protocols/tls_sec_prot/tls_sec_prot.c
        nanostack/source/security/protocols/tls_sec_prot/tls_sec_prot_lib.c
        nanostack/source/service_libs/blacklist/blacklist.c
        nanostack/source/service_libs/etx/etx.c
        nanostack/source/service_libs/fnv_hash/fnv_hash.c
        nanostack/source/service_libs/hmac/hmac_md.c
        nanostack/source/service_libs/ieee_802_11/ieee_802_11.c
        nanostack/source/service_libs/mac_neighbor_table/mac_neighbor_table.c
        nanostack/source/service_libs/nd_proxy/nd_proxy.c
        nanostack/source/service_libs/nist_aes_kw/nist_aes_kw.c
        nanostack/source/service_libs/random_early_detection/random_early_detection.c
        nanostack/source/service_libs/sha256/ns_sha256.c
        nanostack/source/service_libs/sha256/shalib.c
        nanostack/source/service_libs/trickle/trickle.c
        nanostack/source/service_libs/utils/isqrt.c
        nanostack/source/service_libs/utils/ns_file_system.c
        nanostack/source/service_libs/utils/ns_time.c
        # Excluded nanostack/source/service_libs/whiteboard/whiteboard.c
        nanostack-event-loop/source/event.c
        nanostack-event-loop/source/system_timer.c
        mbed-client-libservice/source/libBits/common_functions.c
        mbed-client-libservice/source/libip6string/ip6tos.c
        mbed-client-libservice/source/libip6string/stoip6.c
        mbed-client-libservice/source/libList/ns_list.c
        mbed-client-libservice/source/libtrace/ns_trace.c
        # Excluded mbed-client-libservice/source/nvmHelper
    )
    target_include_directories(wsnode PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        nanostack/source/
        mbed-trace/
        mbed-client-libservice/
        nanostack-event-loop/
        nanostack/
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
        common/bus_uart.c
        common/hal_interrupt.c
        common/os_scheduler.c
        common/os_timer.c
        common/log.c
        common/rand.c
        common/slist.c
        common/spinel_buffer.c
        mbed-client-libservice/source/libBits/common_functions.c
        mbed-client-libservice/source/libip6string/ip6tos.c
        mbed-client-libservice/source/libip6string/stoip6.c
        mbed-client-libservice/source/libList/ns_list.c
        mbed-client-libservice/source/libtrace/ns_trace.c
        nanostack-event-loop/source/event.c
        nanostack-event-loop/source/system_timer.c
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
        # Excluded app_wshwsim/fhss/fhss_test_api.c
    )
    target_include_directories(wshwsim PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        app_wshwsim/
        mbed-trace/
        mbed-client-libservice/
        nanostack-event-loop/
        nanostack/
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
        app_wssimserver/wssimserver.c)
    target_include_directories(wssimserver PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    install(TARGETS wssimserver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

endif()
