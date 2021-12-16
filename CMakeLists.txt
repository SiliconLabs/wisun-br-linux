cmake_minimum_required(VERSION  3.16.3)
project(wsbrd)
include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckCCompilerFlag)

# Greatly improve warning messages. There is no reason to not enable that.
check_c_compiler_flag(-Wall CC_HAVE_WALL)
if(CC_HAVE_WALL)
    add_compile_options(-Wall)
endif()

# In come case, backtraces are not available without that flags. Increase size
# of the  binary file, but can be stripped.
check_c_compiler_flag(-funwind-tables CC_HAVE_UNWIND_TABLES)
if(CC_HAVE_UNWIND_TABLES)
    add_compile_options(-funwind-tables)
endif()

add_custom_target(check_git
    ALL
    BYPRODUCTS version.c
    COMMENT "Checking the git repository for changes..."
    COMMAND ${CMAKE_SOURCE_DIR}/version.sh ${CMAKE_SOURCE_DIR} version.c)

# Uncomment these to get fake random numbers (note: since Wi-SUN also relies on
# timers, uncommenting that is not sufficient to get reproducible run)
# add_compile_definitions(RANDLIB_PRNG)
# add_compile_definitions(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
# add_compile_definitions(MBEDTLS_TEST_NULL_ENTROPY)

add_compile_definitions(NO_TCP)

add_executable(wshwsim
    version.c
    host-mac/sl_wsrcp.c
    host-mac/sl_wsrcp_mac.c
    host-mac/sl_rf_driver.c
    host-mac/ns_monitor.c
    host-mac/hal_fhss_timer.c
    host-mac/hal_random.c
    host-common/bus_uart.c
    host-common/hal_interrupt.c
    host-common/os_scheduler.c
    host-common/os_timer.c
    host-common/log.c
    host-common/slist.c
    host-common/spinel.c
    host-common/spinel_buffer.c
    mbed-client-libservice/source/libBits/common_functions.c
    # Excluded mbed-client-libservice/source/libip4string
    mbed-client-libservice/source/libip6string/ip6tos.c
    mbed-client-libservice/source/libip6string/stoip6.c
    mbed-client-libservice/source/libList/ns_list.c
    mbed-client-libservice/source/nsdynmemLIB/nsdynmemLIB.c
    mbed-client-randlib/source/randLIB.c
    mbed-trace/source/mbed_trace.c
    nanostack-event-loop/source/event.c
    nanostack-event-loop/source/system_timer.c
    nanostack/source/MAC/IEEE802_15_4/mac_cca_threshold.c
    nanostack/source/MAC/IEEE802_15_4/mac_fhss_callbacks.c
    nanostack/source/MAC/IEEE802_15_4/mac_filter.c
    nanostack/source/MAC/IEEE802_15_4/mac_header_helper_functions.c
    nanostack/source/MAC/IEEE802_15_4/mac_indirect_data.c
    nanostack/source/MAC/IEEE802_15_4/mac_mcps_sap.c
    nanostack/source/MAC/IEEE802_15_4/mac_mlme.c
    nanostack/source/MAC/IEEE802_15_4/mac_mode_switch.c
    nanostack/source/MAC/IEEE802_15_4/mac_pd_sap.c
    nanostack/source/MAC/IEEE802_15_4/mac_security_mib.c
    nanostack/source/MAC/IEEE802_15_4/mac_timer.c
    nanostack/source/MAC/IEEE802_15_4/sw_mac.c
    nanostack/source/MAC/rf_driver_storage.c
    nanostack/source/Service_Libs/CCM_lib/ccm_security.c
    nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls_adapter.c
    nanostack/source/Service_Libs/fhss/channel_functions.c
    nanostack/source/Service_Libs/fhss/channel_list.c
    nanostack/source/Service_Libs/fhss/fhss_common.c
    nanostack/source/Service_Libs/fhss/fhss_configuration_interface.c
    nanostack/source/Service_Libs/fhss/fhss_statistics.c
    nanostack/source/Service_Libs/fhss/fhss_ws.c
    # Excluded nanostack/source/Service_Libs/fhss/fhss_test_api.c
    # Excluded nanostack/source/Service_Libs/fhss/fhss_ws_empty_functions.c
)

target_include_directories(wshwsim PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    mbed-trace/
    mbed-client-libservice
    mbed-client-randlib/
    nanostack-event-loop/
    nanostack/
)
target_include_directories(wshwsim PRIVATE
    mbed-client-libservice/mbed-client-libservice/
    mbed-client-randlib/mbed-client-randlib/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)

target_compile_definitions(wshwsim PRIVATE MBED_CONF_NANOSTACK_CONFIGURATION=ws_border_router)
target_compile_definitions(wshwsim PRIVATE MBED_CONF_MBED_TRACE_ENABLE)
# target_compile_definitions(wshwsim PRIVATE FHSS_CHANNEL_DEBUG)
# target_compile_definitions(wshwsim PRIVATE TIMING_TOOL_TRACES)
# target_compile_definitions(wshwsim PRIVATE EXTRA_DEBUG_INFO)
target_compile_definitions(wshwsim PRIVATE STANDARD_MALLOC)

add_executable(wsbrd
    version.c
    host-net/wsbr.c
    host-net/wsbr_mac.c
    host-net/wsbr_fhss_mac.c
    host-net/wsbr_fhss_net.c
    host-net/tun.c
    host-net/named_values.c
    host-net/commandline.c
    host-net/os_whiteboard.c
    host-common/bus_uart.c
    host-common/hal_interrupt.c
    host-common/os_timer.c
    host-common/os_scheduler.c
    host-common/log.c
    host-common/slist.c
    host-common/spinel.c
    host-common/spinel_buffer.c
    nanostack/source/Service_Libs/fhss/channel_list.c
    nanostack/source/BorderRouter/border_router.c
    nanostack/source/6LoWPAN/adaptation_interface.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/network_lib.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan_bootstrap.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan_interface.c
    nanostack/source/6LoWPAN/Fragmentation/cipv6_fragmenter.c
    nanostack/source/6LoWPAN/IPHC_Decode/6lowpan_iphc.c
    nanostack/source/6LoWPAN/IPHC_Decode/iphc_compress.c
    nanostack/source/6LoWPAN/IPHC_Decode/iphc_decompress.c
    nanostack/source/6LoWPAN/IPHC_Decode/lowpan_context.c
    nanostack/source/6LoWPAN/MAC/beacon_handler.c
    nanostack/source/6LoWPAN/MAC/mac_data_poll.c
    nanostack/source/6LoWPAN/MAC/mac_helper.c
    nanostack/source/6LoWPAN/MAC/mac_ie_lib.c
    nanostack/source/6LoWPAN/MAC/mac_pairwise_key.c
    nanostack/source/6LoWPAN/MAC/mac_response_handler.c
    # Excluded nanostack/source/6LoWPAN/Mesh
    nanostack/source/6LoWPAN/ND/nd_router_object.c
    # Excluded nanostack/source/6LoWPAN/NVM
    # Excluded nanostack/source/6LoWPAN/Thread
    nanostack/source/6LoWPAN/ws/ws_bbr_api.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap_6lbr.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap_ffn.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap_lfn.c
    nanostack/source/6LoWPAN/ws/ws_cfg_settings.c
    nanostack/source/6LoWPAN/ws/ws_common.c
    nanostack/source/6LoWPAN/ws/ws_eapol_auth_relay.c
    nanostack/source/6LoWPAN/ws/ws_eapol_pdu.c
    nanostack/source/6LoWPAN/ws/ws_eapol_relay.c
    nanostack/source/6LoWPAN/ws/ws_eapol_relay_lib.c
    # Excluded nanostack/source/6LoWPAN/ws/ws_empty_functions.c
    nanostack/source/6LoWPAN/ws/ws_ie_lib.c
    nanostack/source/6LoWPAN/ws/ws_llc_data_service.c
    nanostack/source/6LoWPAN/ws/ws_management_api.c
    nanostack/source/6LoWPAN/ws/ws_mpx_header.c
    nanostack/source/6LoWPAN/ws/ws_neighbor_class.c
    nanostack/source/6LoWPAN/ws/ws_pae_auth.c
    nanostack/source/6LoWPAN/ws/ws_pae_controller.c
    nanostack/source/6LoWPAN/ws/ws_pae_key_storage.c
    nanostack/source/6LoWPAN/ws/ws_pae_lib.c
    nanostack/source/6LoWPAN/ws/ws_pae_nvm_store.c
    nanostack/source/6LoWPAN/ws/ws_pae_nvm_data.c
    nanostack/source/6LoWPAN/ws/ws_pae_supp.c
    nanostack/source/6LoWPAN/ws/ws_pae_time.c
    nanostack/source/6LoWPAN/ws/ws_pae_timers.c
    nanostack/source/6LoWPAN/ws/ws_phy.c
    nanostack/source/6LoWPAN/ws/ws_stats.c
    nanostack/source/6LoWPAN/ws/ws_test_api.c
    nanostack/source/Common_Protocols/icmpv6.c
    nanostack/source/Common_Protocols/icmpv6_prefix.c
    nanostack/source/Common_Protocols/icmpv6_radv.c
    nanostack/source/Common_Protocols/ipv6.c
    nanostack/source/Common_Protocols/ipv6_flow.c
    nanostack/source/Common_Protocols/ipv6_fragmentation.c
    nanostack/source/Common_Protocols/ipv6_resolution.c
    nanostack/source/Common_Protocols/mld.c
    nanostack/source/Common_Protocols/tcp.c
    nanostack/source/Common_Protocols/udp.c
    nanostack/source/Core/buffer_dyn.c
    nanostack/source/Core/ns_address_internal.c
    nanostack/source/Core/ns_monitor.c
    nanostack/source/Core/ns_socket.c
    nanostack/source/Core/sockbuf.c
    nanostack/source/DHCPv6_client/dhcpv6_client_service.c
    nanostack/source/DHCPv6_Server/DHCPv6_Server_service.c
    nanostack/source/ipv6_stack/ipv6_routing_table.c
    nanostack/source/ipv6_stack/protocol_ipv6.c
    nanostack/source/libDHCPv6/dhcp_service_api.c
    nanostack/source/libDHCPv6/libDHCPv6.c
    nanostack/source/libDHCPv6/libDHCPv6_server.c
    nanostack/source/libDHCPv6/libDHCPv6_vendordata.c
    nanostack/source/libNET/src/net_short_address_extension.c
    nanostack/source/libNET/src/net_dns.c
    nanostack/source/libNET/src/multicast_api.c
    nanostack/source/libNET/src/net_6lowpan_parameter_api.c
    # nanostack/source/libNET/src/net_test.c
    nanostack/source/libNET/src/net_rpl.c
    nanostack/source/libNET/src/ns_net.c
    nanostack/source/libNET/src/socket_api.c
    nanostack/source/libNET/src/net_ipv6.c
    # Excluded nanostack/source/libNET/src/net_mle.c
    nanostack/source/libNET/src/net_load_balance.c
    nanostack/source/MAC/rf_driver_storage.c
    nanostack/source/MAC/ethernet/ethernet_mac_api.c
    # Excluded nanostack/source/MAC/serial
    # Excluded nanostack/source/MAC/IEEE802_15_4
    # Excluded nanostack/source/MAC/virtual_rf
    nanostack/source/MLE/mle.c
    nanostack/source/MLE/mle_tlv.c
    nanostack/source/MPL/mpl.c
    nanostack/source/NWK_INTERFACE/protocol_core.c
    nanostack/source/NWK_INTERFACE/protocol_core_sleep.c
    nanostack/source/NWK_INTERFACE/protocol_stats.c
    nanostack/source/NWK_INTERFACE/protocol_timer.c
    nanostack/source/RPL/rpl_control.c
    nanostack/source/RPL/rpl_mrhof.c
    nanostack/source/RPL/rpl_downward.c
    nanostack/source/RPL/rpl_data.c
    nanostack/source/RPL/rpl_objective.c
    nanostack/source/RPL/rpl_of0.c
    nanostack/source/RPL/rpl_policy.c
    nanostack/source/RPL/rpl_upward.c
    nanostack/source/Security/eapol/eapol_helper.c
    nanostack/source/Security/eapol/kde_helper.c
    nanostack/source/Security/kmp/kmp_addr.c
    nanostack/source/Security/kmp/kmp_api.c
    nanostack/source/Security/kmp/kmp_eapol_pdu_if.c
    nanostack/source/Security/kmp/kmp_socket_if.c
    # Excluded nanostack/source/Security/PANA
    nanostack/source/Security/PANA/pana_eap_header.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
    nanostack/source/Security/protocols/key_sec_prot/key_sec_prot.c
    nanostack/source/Security/protocols/msg_sec_prot/msg_sec_prot.c
    nanostack/source/Security/protocols/radius_sec_prot/avp_helper.c
    nanostack/source/Security/protocols/radius_sec_prot/radius_client_sec_prot.c
    nanostack/source/Security/protocols/sec_prot_certs.c
    nanostack/source/Security/protocols/sec_prot_keys.c
    nanostack/source/Security/protocols/sec_prot_lib.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot_lib.c
    # Excluded nanostack/source/Security/TLS
    nanostack/source/Service_Libs/blacklist/blacklist.c
    nanostack/source/Service_Libs/CCM_lib/ccm_security.c
    nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls_adapter.c
    # Excluded nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls.c
    nanostack/source/Service_Libs/etx/etx.c
    nanostack/source/Service_Libs/fnv_hash/fnv_hash.c
    nanostack/source/Service_Libs/hmac/hmac_md.c
    nanostack/source/Service_Libs/ieee_802_11/ieee_802_11.c
    nanostack/source/Service_Libs/load_balance/load_balance.c
    nanostack/source/Service_Libs/mac_neighbor_table/mac_neighbor_table.c
    # Excluded nanostack/source/Service_Libs/mdns
    nanostack/source/Service_Libs/mle_service/mle_service_buffer.c
    nanostack/source/Service_Libs/mle_service/mle_service.c
    nanostack/source/Service_Libs/mle_service/mle_service_frame_counter_table.c
    nanostack/source/Service_Libs/mle_service/mle_service_interface.c
    nanostack/source/Service_Libs/mle_service/mle_service_security.c
    nanostack/source/Service_Libs/nd_proxy/nd_proxy.c
    nanostack/source/Service_Libs/Neighbor_cache/neighbor_cache.c
    nanostack/source/Service_Libs/nist_aes_kw/nist_aes_kw.c
    nanostack/source/Service_Libs/pan_blacklist/pan_blacklist.c
    nanostack/source/Service_Libs/random_early_detection/random_early_detection.c
    nanostack/source/Service_Libs/SHA256_Lib/ns_sha256.c
    nanostack/source/Service_Libs/SHA256_Lib/shalib.c
    nanostack/source/Service_Libs/Trickle/trickle.c
    nanostack/source/Service_Libs/utils/isqrt.c
    nanostack/source/Service_Libs/utils/ns_conf.c
    nanostack/source/Service_Libs/utils/ns_crc.c
    nanostack/source/Service_Libs/utils/ns_file_system.c
    nanostack/source/Service_Libs/utils/ns_time.c
    # Excluded nanostack/source/Service_Libs/whiteboard/whiteboard.c
    # Excluded nanostack-event-loop/source/ns_timeout.c
    nanostack-event-loop/source/event.c
    nanostack-event-loop/source/system_timer.c
    mbed-client-libservice/source/IPv6_fcf_lib/ip_fsc.c
    mbed-client-libservice/source/libBits/common_functions.c
    # Excluded mbed-client-libservice/source/libip4string
    mbed-client-libservice/source/libip6string/ip6tos.c
    mbed-client-libservice/source/libip6string/stoip6.c
    mbed-client-libservice/source/libList/ns_list.c
    mbed-client-libservice/source/nsdynmemLIB/nsdynmemLIB.c
    # Excluded mbed-client-libservice/source/nvmHelper
    mbed-client-randlib/source/randLIB.c
    mbed-trace/source/mbed_trace.c
    mbedtls/library/aes.c
    mbedtls/library/asn1parse.c
    mbedtls/library/asn1write.c
    mbedtls/library/base64.c
    mbedtls/library/bignum.c
    mbedtls/library/ccm.c
    mbedtls/library/cipher.c
    mbedtls/library/cipher_wrap.c
    mbedtls/library/cipher_wrap.c
    mbedtls/library/ctr_drbg.c
    mbedtls/library/debug.c
    mbedtls/library/ecdh.c
    mbedtls/library/ecdsa.c
    mbedtls/library/ecp.c
    mbedtls/library/ecp_curves.c
    mbedtls/library/entropy.c
    mbedtls/library/entropy_poll.c
    mbedtls/library/hmac_drbg.c
    mbedtls/library/md.c
    mbedtls/library/nist_kw.c
    mbedtls/library/oid.c
    mbedtls/library/pem.c
    mbedtls/library/pk.c
    mbedtls/library/pkparse.c
    mbedtls/library/pk_wrap.c
    mbedtls/library/platform_util.c
    mbedtls/library/sha1.c
    mbedtls/library/sha256.c
    mbedtls/library/sha512.c
    mbedtls/library/ssl_ciphersuites.c
    mbedtls/library/ssl_cli.c
    mbedtls/library/ssl_msg.c
    mbedtls/library/ssl_srv.c
    mbedtls/library/ssl_tls.c
    mbedtls/library/x509.c
    mbedtls/library/x509_crl.c
    mbedtls/library/x509_crt.c
)

target_include_directories(wsbrd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    mbedtls/include/
    mbed-trace/
    mbed-client-randlib/
    mbed-client-libservice/
    nanostack-event-loop/
    nanostack/
)
target_include_directories(wsbrd PRIVATE
    mbedtls/
    mbed-client-randlib/mbed-client-randlib/
    mbed-client-libservice/mbed-client-libservice/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)
target_compile_definitions(wsbrd PRIVATE MBED_CONF_NANOSTACK_CONFIGURATION=ws_border_router)
target_compile_definitions(wsbrd PRIVATE MBED_CONF_MBED_TRACE_ENABLE)
# target_compile_definitions(wsbrd PRIVATE EXTRA_DEBUG_INFO)
target_compile_definitions(wsbrd PRIVATE STANDARD_MALLOC)

add_executable(wsnode
    version.c
    host-net/wsrouter.c
    host-net/wsbr_mac.c
    host-net/wsbr_fhss_mac.c
    host-net/wsbr_fhss_net.c
    host-net/commandline.c
    host-net/named_values.c
    host-common/bus_uart.c
    host-common/hal_interrupt.c
    host-common/os_timer.c
    host-common/os_scheduler.c
    host-common/log.c
    host-common/slist.c
    host-common/spinel.c
    host-common/spinel_buffer.c
    nanostack/source/Service_Libs/fhss/channel_list.c
    # nanostack/source/BorderRouter/border_router.c
    nanostack/source/6LoWPAN/adaptation_interface.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/network_lib.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan_bootstrap.c
    nanostack/source/6LoWPAN/Bootstraps/Generic/protocol_6lowpan_interface.c
    nanostack/source/6LoWPAN/Fragmentation/cipv6_fragmenter.c
    nanostack/source/6LoWPAN/IPHC_Decode/6lowpan_iphc.c
    nanostack/source/6LoWPAN/IPHC_Decode/iphc_compress.c
    nanostack/source/6LoWPAN/IPHC_Decode/iphc_decompress.c
    nanostack/source/6LoWPAN/IPHC_Decode/lowpan_context.c
    nanostack/source/6LoWPAN/MAC/beacon_handler.c
    nanostack/source/6LoWPAN/MAC/mac_data_poll.c
    nanostack/source/6LoWPAN/MAC/mac_helper.c
    nanostack/source/6LoWPAN/MAC/mac_ie_lib.c
    nanostack/source/6LoWPAN/MAC/mac_pairwise_key.c
    nanostack/source/6LoWPAN/MAC/mac_response_handler.c
    # Excluded nanostack/source/6LoWPAN/Mesh
    nanostack/source/6LoWPAN/ND/nd_router_object.c
    # Excluded nanostack/source/6LoWPAN/NVM
    # Excluded nanostack/source/6LoWPAN/Thread
    nanostack/source/6LoWPAN/ws/ws_bbr_api.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap_ffn.c
    nanostack/source/6LoWPAN/ws/ws_bootstrap_lfn.c
    nanostack/source/6LoWPAN/ws/ws_cfg_settings.c
    nanostack/source/6LoWPAN/ws/ws_common.c
    nanostack/source/6LoWPAN/ws/ws_eapol_auth_relay.c
    nanostack/source/6LoWPAN/ws/ws_eapol_pdu.c
    nanostack/source/6LoWPAN/ws/ws_eapol_relay.c
    nanostack/source/6LoWPAN/ws/ws_eapol_relay_lib.c
    # Excluded nanostack/source/6LoWPAN/ws/ws_empty_functions.c
    nanostack/source/6LoWPAN/ws/ws_ie_lib.c
    nanostack/source/6LoWPAN/ws/ws_llc_data_service.c
    nanostack/source/6LoWPAN/ws/ws_management_api.c
    nanostack/source/6LoWPAN/ws/ws_mpx_header.c
    nanostack/source/6LoWPAN/ws/ws_neighbor_class.c
    nanostack/source/6LoWPAN/ws/ws_pae_auth.c
    nanostack/source/6LoWPAN/ws/ws_pae_controller.c
    nanostack/source/6LoWPAN/ws/ws_pae_key_storage.c
    nanostack/source/6LoWPAN/ws/ws_pae_lib.c
    nanostack/source/6LoWPAN/ws/ws_pae_nvm_store.c
    nanostack/source/6LoWPAN/ws/ws_pae_nvm_data.c
    nanostack/source/6LoWPAN/ws/ws_pae_supp.c
    nanostack/source/6LoWPAN/ws/ws_pae_time.c
    nanostack/source/6LoWPAN/ws/ws_pae_timers.c
    nanostack/source/6LoWPAN/ws/ws_phy.c
    nanostack/source/6LoWPAN/ws/ws_stats.c
    nanostack/source/6LoWPAN/ws/ws_test_api.c
    nanostack/source/Common_Protocols/icmpv6.c
    nanostack/source/Common_Protocols/icmpv6_prefix.c
    nanostack/source/Common_Protocols/icmpv6_radv.c
    nanostack/source/Common_Protocols/ipv6.c
    nanostack/source/Common_Protocols/ipv6_flow.c
    nanostack/source/Common_Protocols/ipv6_fragmentation.c
    nanostack/source/Common_Protocols/ipv6_resolution.c
    nanostack/source/Common_Protocols/mld.c
    nanostack/source/Common_Protocols/tcp.c
    nanostack/source/Common_Protocols/udp.c
    nanostack/source/Core/buffer_dyn.c
    nanostack/source/Core/ns_address_internal.c
    nanostack/source/Core/ns_monitor.c
    nanostack/source/Core/ns_socket.c
    nanostack/source/Core/sockbuf.c
    nanostack/source/DHCPv6_client/dhcpv6_client_service.c
    nanostack/source/DHCPv6_Server/DHCPv6_Server_service.c
    nanostack/source/ipv6_stack/ipv6_routing_table.c
    nanostack/source/ipv6_stack/protocol_ipv6.c
    nanostack/source/libDHCPv6/dhcp_service_api.c
    nanostack/source/libDHCPv6/libDHCPv6.c
    nanostack/source/libDHCPv6/libDHCPv6_server.c
    nanostack/source/libDHCPv6/libDHCPv6_vendordata.c
    nanostack/source/libNET/src/net_short_address_extension.c
    nanostack/source/libNET/src/net_dns.c
    nanostack/source/libNET/src/multicast_api.c
    nanostack/source/libNET/src/net_6lowpan_parameter_api.c
    # nanostack/source/libNET/src/net_test.c
    nanostack/source/libNET/src/net_rpl.c
    nanostack/source/libNET/src/ns_net.c
    nanostack/source/libNET/src/socket_api.c
    nanostack/source/libNET/src/net_ipv6.c
    # Excluded nanostack/source/libNET/src/net_mle.c
    nanostack/source/libNET/src/net_load_balance.c
    nanostack/source/MAC/rf_driver_storage.c
    nanostack/source/MAC/ethernet/ethernet_mac_api.c
    # Excluded nanostack/source/MAC/serial
    # Excluded nanostack/source/MAC/IEEE802_15_4
    # Excluded nanostack/source/MAC/virtual_rf
    nanostack/source/MLE/mle.c
    nanostack/source/MLE/mle_tlv.c
    nanostack/source/MPL/mpl.c
    nanostack/source/NWK_INTERFACE/protocol_core.c
    nanostack/source/NWK_INTERFACE/protocol_core_sleep.c
    nanostack/source/NWK_INTERFACE/protocol_stats.c
    nanostack/source/NWK_INTERFACE/protocol_timer.c
    nanostack/source/RPL/rpl_control.c
    nanostack/source/RPL/rpl_mrhof.c
    nanostack/source/RPL/rpl_downward.c
    nanostack/source/RPL/rpl_data.c
    nanostack/source/RPL/rpl_objective.c
    nanostack/source/RPL/rpl_of0.c
    nanostack/source/RPL/rpl_policy.c
    nanostack/source/RPL/rpl_upward.c
    nanostack/source/Security/eapol/eapol_helper.c
    nanostack/source/Security/eapol/kde_helper.c
    nanostack/source/Security/kmp/kmp_addr.c
    nanostack/source/Security/kmp/kmp_api.c
    nanostack/source/Security/kmp/kmp_eapol_pdu_if.c
    nanostack/source/Security/kmp/kmp_socket_if.c
    # Excluded nanostack/source/Security/PANA
    nanostack/source/Security/PANA/pana_eap_header.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
    nanostack/source/Security/protocols/key_sec_prot/key_sec_prot.c
    nanostack/source/Security/protocols/msg_sec_prot/msg_sec_prot.c
    nanostack/source/Security/protocols/radius_sec_prot/avp_helper.c
    nanostack/source/Security/protocols/radius_sec_prot/radius_client_sec_prot.c
    nanostack/source/Security/protocols/sec_prot_certs.c
    nanostack/source/Security/protocols/sec_prot_keys.c
    nanostack/source/Security/protocols/sec_prot_lib.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot_lib.c
    # Excluded nanostack/source/Security/TLS
    nanostack/source/Service_Libs/blacklist/blacklist.c
    nanostack/source/Service_Libs/CCM_lib/ccm_security.c
    nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls_adapter.c
    # Excluded nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls.c
    nanostack/source/Service_Libs/etx/etx.c
    nanostack/source/Service_Libs/fnv_hash/fnv_hash.c
    nanostack/source/Service_Libs/hmac/hmac_md.c
    nanostack/source/Service_Libs/ieee_802_11/ieee_802_11.c
    nanostack/source/Service_Libs/load_balance/load_balance.c
    nanostack/source/Service_Libs/mac_neighbor_table/mac_neighbor_table.c
    # Excluded nanostack/source/Service_Libs/mdns
    nanostack/source/Service_Libs/mle_service/mle_service_buffer.c
    nanostack/source/Service_Libs/mle_service/mle_service.c
    nanostack/source/Service_Libs/mle_service/mle_service_frame_counter_table.c
    nanostack/source/Service_Libs/mle_service/mle_service_interface.c
    nanostack/source/Service_Libs/mle_service/mle_service_security.c
    nanostack/source/Service_Libs/nd_proxy/nd_proxy.c
    nanostack/source/Service_Libs/Neighbor_cache/neighbor_cache.c
    nanostack/source/Service_Libs/nist_aes_kw/nist_aes_kw.c
    nanostack/source/Service_Libs/pan_blacklist/pan_blacklist.c
    nanostack/source/Service_Libs/random_early_detection/random_early_detection.c
    nanostack/source/Service_Libs/SHA256_Lib/ns_sha256.c
    nanostack/source/Service_Libs/SHA256_Lib/shalib.c
    nanostack/source/Service_Libs/Trickle/trickle.c
    nanostack/source/Service_Libs/utils/isqrt.c
    nanostack/source/Service_Libs/utils/ns_conf.c
    nanostack/source/Service_Libs/utils/ns_crc.c
    nanostack/source/Service_Libs/utils/ns_file_system.c
    nanostack/source/Service_Libs/utils/ns_time.c
    # Excluded nanostack/source/Service_Libs/whiteboard/whiteboard.c
    # Excluded nanostack-event-loop/source/ns_timeout.c
    nanostack-event-loop/source/event.c
    nanostack-event-loop/source/system_timer.c
    mbed-client-libservice/source/IPv6_fcf_lib/ip_fsc.c
    mbed-client-libservice/source/libBits/common_functions.c
    # Excluded mbed-client-libservice/source/libip4string
    mbed-client-libservice/source/libip6string/ip6tos.c
    mbed-client-libservice/source/libip6string/stoip6.c
    mbed-client-libservice/source/libList/ns_list.c
    mbed-client-libservice/source/nsdynmemLIB/nsdynmemLIB.c
    # Excluded mbed-client-libservice/source/nvmHelper
    mbed-client-randlib/source/randLIB.c
    mbed-trace/source/mbed_trace.c
    mbedtls/library/aes.c
    mbedtls/library/asn1parse.c
    mbedtls/library/asn1write.c
    mbedtls/library/base64.c
    mbedtls/library/bignum.c
    mbedtls/library/ccm.c
    mbedtls/library/cipher.c
    mbedtls/library/cipher_wrap.c
    mbedtls/library/cipher_wrap.c
    mbedtls/library/ctr_drbg.c
    mbedtls/library/debug.c
    mbedtls/library/ecdh.c
    mbedtls/library/ecdsa.c
    mbedtls/library/ecp.c
    mbedtls/library/ecp_curves.c
    mbedtls/library/entropy.c
    mbedtls/library/entropy_poll.c
    mbedtls/library/hmac_drbg.c
    mbedtls/library/md5.c
    mbedtls/library/md.c
    mbedtls/library/nist_kw.c
    mbedtls/library/oid.c
    mbedtls/library/pem.c
    mbedtls/library/pk.c
    mbedtls/library/pkparse.c
    mbedtls/library/pk_wrap.c
    mbedtls/library/platform_util.c
    mbedtls/library/sha1.c
    mbedtls/library/sha256.c
    mbedtls/library/sha512.c
    mbedtls/library/ssl_ciphersuites.c
    mbedtls/library/ssl_cli.c
    mbedtls/library/ssl_msg.c
    mbedtls/library/ssl_srv.c
    mbedtls/library/ssl_tls.c
    mbedtls/library/x509.c
    mbedtls/library/x509_crl.c
    mbedtls/library/x509_crt.c
)

target_include_directories(wsnode PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    mbedtls/include/
    mbed-trace/
    mbed-client-randlib/
    mbed-client-libservice
    nanostack-event-loop/
    nanostack/
)
target_include_directories(wsnode PRIVATE
    mbedtls/
    mbed-client-randlib/mbed-client-randlib/
    mbed-client-libservice/mbed-client-libservice/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)

target_compile_definitions(wsnode PRIVATE MBED_CONF_NANOSTACK_CONFIGURATION=ws_router)
target_compile_definitions(wsnode PRIVATE MBED_CONF_MBED_TRACE_ENABLE)
# target_compile_definitions(wsnode PRIVATE EXTRA_DEBUG_INFO)
target_compile_definitions(wsnode PRIVATE STANDARD_MALLOC)


find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL_ROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
target_link_libraries(wsbrd PRIVATE PkgConfig::LIBNL_ROUTE)
pkg_check_modules(LIBSYSTEMD IMPORTED_TARGET libsystemd)
if(LIBSYSTEMD_FOUND)
    target_compile_definitions(wsbrd PRIVATE HAVE_LIBSYSTEMD)
    target_sources(wsbrd PRIVATE host-net/dbus.c)
    target_link_libraries(wsbrd PRIVATE PkgConfig::LIBSYSTEMD)
endif()

# Note that old libpcap releases didn't provide pkg-config file and are not
# detected by the line below. The user have to compile without support for
# libpcap or manually defines the flags.
pkg_check_modules(LIBPCAP IMPORTED_TARGET libpcap)
if(LIBPCAP_FOUND)
    target_compile_definitions(wshwsim PRIVATE HAVE_LIBPCAP)
    target_link_libraries(wshwsim PRIVATE PkgConfig::LIBPCAP)
endif()

check_include_file(backtrace.h BACKTRACE_FOUND)
if(BACKTRACE_FOUND)
    target_compile_definitions(wsbrd PRIVATE HAVE_BACKTRACE)
    target_compile_definitions(wsnode PRIVATE HAVE_BACKTRACE)
    target_compile_definitions(wshwsim PRIVATE HAVE_BACKTRACE)
    target_sources(wsbrd PRIVATE host-common/backtrace.c)
    target_sources(wsnode PRIVATE host-common/backtrace.c)
    target_sources(wshwsim PRIVATE host-common/backtrace.c)
    target_link_libraries(wsbrd PRIVATE backtrace)
    target_link_libraries(wsnode PRIVATE backtrace)
    target_link_libraries(wshwsim PRIVATE backtrace)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(wsbrd PRIVATE Threads::Threads)
target_link_libraries(wsnode PRIVATE Threads::Threads)
target_link_libraries(wshwsim PRIVATE Threads::Threads)

install(TARGETS wsbrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# FIXME: use ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/wsbrd and report this value in
# the code
install(DIRECTORY DESTINATION /var/lib/wsbrd)
install(FILES
    misc/com.silabs.Wisun.BorderRouter.service
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/dbus-1/system-services)
install(FILES
    misc/wisun-borderouter.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
# FIXME: we try to avoid PATH hardcoding, but dbus does not watch
# /usr/local/share/dbus-1/system.d
install(FILES
    misc/com.silabs.Wisun.BorderRouter.conf
    DESTINATION /etc/dbus-1/system.d)
install(FILES
    CHANGES.md
    README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES
    examples/wsbrd.conf
    examples/br_cert.pem
    examples/br_key.pem
    examples/ca_cert.pem
    examples/node_cert.pem
    examples/node_key.pem
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)
