cmake_minimum_required(VERSION  3.16.3)
project(wisun-host)
# These option only work with gcc, but we do not plan to compiler with another
# compiler.
add_compile_options(-Wall)

add_executable(wisun-mac
    wsmac.c
    wsmac_ns_monitor.c
    bus_uart.c
    hal_interrupt.c
    hal_fhss_timer.c
    hal_random.c
    os_scheduler.c
    os_timer.c
    slist.c
    mbed-client-libservice/source/libBits/common_functions.c
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
    nanostack/source/MAC/IEEE802_15_4/mac_pd_sap.c
    nanostack/source/MAC/IEEE802_15_4/mac_security_mib.c
    nanostack/source/MAC/IEEE802_15_4/mac_timer.c
    nanostack/source/MAC/IEEE802_15_4/sw_mac.c
    nanostack/source/MAC/rf_driver_storage.c
    nanostack/source/Service_Libs/CCM_lib/ccm_security.c
    nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls_adapter.c
)

target_include_directories(wisun-mac PRIVATE
    mbed-trace/
    mbed-client-libservice
    mbed-client-libservice/mbed-client-libservice/
    mbed-client-randlib/mbed-client-randlib/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)

target_compile_definitions(wisun-mac PRIVATE MBED_CONF_NANOSTACK_CONFIGURATION=ws_border_router)
target_compile_definitions(wisun-mac PRIVATE MBED_CONF_MBED_TRACE_ENABLE)
target_compile_definitions(wisun-mac PRIVATE EXTRA_DEBUG_INFO)
target_compile_definitions(wisun-mac PRIVATE STANDARD_MALLOC)

add_executable(wisun-br
    wsbr.c
    wsbr_mac.c
    wsbr_fhss.c
    bus_uart.c
    bus_spi.c
    tun.c
    hal_interrupt.c
    hal_fhss_timer.c
    hal_random.c
    os_timer.c
    os_scheduler.c
    slist.c
    spinel.c
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
    nanostack/source/libNET/src/net_test.c
    nanostack/source/libNET/src/net_rpl.c
    nanostack/source/libNET/src/ns_net.c
    nanostack/source/libNET/src/socket_api.c
    nanostack/source/libNET/src/net_ipv6.c
    nanostack/source/libNET/src/net_mle.c
    nanostack/source/libNET/src/net_load_balance.c
    nanostack/source/MAC/rf_driver_storage.c
    # Excluded nanostack/source/MAC/serial
    # Excluded nanostack/source/MAC/IEEE802_15_4
    nanostack/source/MAC/ethernet/ethernet_mac_api.c
    # Excluded nanostack/source/MAC/virtual_rf/virtual_rf_client.c
    # Excluded nanostack/source/MAC/virtual_rf/virtual_rf_driver.c
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
    nanostack/source/Security/Common/security_lib.c
    nanostack/source/Security/eapol/eapol_helper.c
    nanostack/source/Security/eapol/kde_helper.c
    nanostack/source/Security/kmp/kmp_addr.c
    nanostack/source/Security/kmp/kmp_api.c
    nanostack/source/Security/kmp/kmp_eapol_pdu_if.c
    nanostack/source/Security/kmp/kmp_socket_if.c
    nanostack/source/Security/PANA/eap_protocol.c
    nanostack/source/Security/PANA/pana_avp.c
    nanostack/source/Security/PANA/pana.c
    nanostack/source/Security/PANA/pana_client.c
    nanostack/source/Security/PANA/pana_eap_header.c
    nanostack/source/Security/PANA/pana_header.c
    nanostack/source/Security/PANA/pana_relay_table.c
    nanostack/source/Security/PANA/pana_server.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/eap_tls_sec_prot_lib.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/eap_tls_sec_prot/supp_eap_tls_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/auth_fwh_sec_prot.c
    nanostack/source/Security/protocols/fwh_sec_prot/supp_fwh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/auth_gkh_sec_prot.c
    nanostack/source/Security/protocols/gkh_sec_prot/supp_gkh_sec_prot.c
    nanostack/source/Security/protocols/key_sec_prot/key_sec_prot.c
    nanostack/source/Security/protocols/radius_sec_prot/avp_helper.c
    nanostack/source/Security/protocols/radius_sec_prot/radius_client_sec_prot.c
    nanostack/source/Security/protocols/sec_prot_certs.c
    nanostack/source/Security/protocols/sec_prot_keys.c
    nanostack/source/Security/protocols/sec_prot_lib.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot.c
    nanostack/source/Security/protocols/tls_sec_prot/tls_sec_prot_lib.c
    nanostack/source/Security/TLS/tls_ccm_crypt.c
    nanostack/source/Security/TLS/tls_lib.c
    nanostack/source/Service_Libs/blacklist/blacklist.c
    nanostack/source/Service_Libs/CCM_lib/ccm_security.c
    nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls_adapter.c
    # Excluded nanostack/source/Service_Libs/CCM_lib/mbedOS/aes_mbedtls.c
    nanostack/source/Service_Libs/etx/etx.c
    nanostack/source/Service_Libs/fhss/channel_functions.c
    nanostack/source/Service_Libs/fhss/channel_list.c
    nanostack/source/Service_Libs/fhss/fhss.c
    nanostack/source/Service_Libs/fhss/fhss_channel.c
    nanostack/source/Service_Libs/fhss/fhss_common.c
    nanostack/source/Service_Libs/fhss/fhss_configuration_interface.c
    nanostack/source/Service_Libs/fhss/fhss_statistics.c
    nanostack/source/Service_Libs/fhss/fhss_test_api.c
    nanostack/source/Service_Libs/fhss/fhss_ws.c
    nanostack/source/Service_Libs/fhss/fhss_ws_empty_functions.c
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
    nanostack/source/Service_Libs/SHA256_Lib/ns_sha256.c
    nanostack/source/Service_Libs/SHA256_Lib/shalib.c
    nanostack/source/Service_Libs/Trickle/trickle.c
    nanostack/source/Service_Libs/utils/isqrt.c
    nanostack/source/Service_Libs/utils/ns_conf.c
    nanostack/source/Service_Libs/utils/ns_crc.c
    nanostack/source/Service_Libs/utils/ns_file_system.c
    nanostack/source/Service_Libs/whiteboard/whiteboard.c
    # Excluded nanostack-event-loop/source/ns_timeout.c
    nanostack-event-loop/source/event.c
    nanostack-event-loop/source/system_timer.c
    mbed-client-libservice/source/IPv6_fcf_lib/ip_fsc.c
    mbed-client-libservice/source/libBits/common_functions.c
    mbed-client-libservice/source/libip4string/ip4tos.c
    mbed-client-libservice/source/libip4string/stoip4.c
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
    mbedtls/library/chacha20.c
    mbedtls/library/chachapoly.c
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
    mbedtls/library/md.c
    mbedtls/library/gcm.c
    mbedtls/library/hmac_drbg.c
    mbedtls/library/md.c
    mbedtls/library/nist_kw.c
    mbedtls/library/oid.c
    mbedtls/library/pem.c
    mbedtls/library/pk.c
    mbedtls/library/pkparse.c
    mbedtls/library/pk_wrap.c
    mbedtls/library/platform_util.c
    mbedtls/library/poly1305.c
    mbedtls/library/rsa.c
    mbedtls/library/rsa_internal.c
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

target_include_directories(wisun-br PRIVATE
    mbedtls/
    mbedtls/include/
    mbed-trace/
    mbed-client-randlib/mbed-client-randlib/
    mbed-client-libservice/
    mbed-client-libservice/mbed-client-libservice/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)
target_compile_definitions(wisun-br PRIVATE MBED_CONF_NANOSTACK_CONFIGURATION=ws_border_router)
target_compile_definitions(wisun-br PRIVATE MBED_CONF_MBED_TRACE_ENABLE)
target_compile_definitions(wisun-br PRIVATE EXTRA_DEBUG_INFO)
target_compile_definitions(wisun-br PRIVATE MBEDTLS_TEST_NULL_ENTROPY)
target_compile_definitions(wisun-br PRIVATE MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
target_compile_definitions(wisun-br PRIVATE RANDLIB_PRNG)
target_compile_definitions(wisun-br PRIVATE STANDARD_MALLOC)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL_ROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
target_link_libraries(wisun-br PRIVATE PkgConfig::LIBNL_ROUTE)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(wisun-br PRIVATE Threads::Threads)
target_link_libraries(wisun-mac PRIVATE Threads::Threads)
