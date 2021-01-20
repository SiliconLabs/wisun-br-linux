cmake_minimum_required(VERSION  3.16.3)
project(wisun-host)

ADD_LIBRARY(wisun-host STATIC
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
    nanostack/source/6LoWPAN/ws/ws_empty_functions.c
    nanostack/source/6LoWPAN/ws/ws_ie_lib.c
    nanostack/source/6LoWPAN/ws/ws_llc_data_service.c
    nanostack/source/6LoWPAN/ws/ws_management_api.c
    nanostack/source/6LoWPAN/ws/ws_mpx_header.c
    nanostack/source/6LoWPAN/ws/ws_neighbor_class.c
    nanostack/source/6LoWPAN/ws/ws_pae_auth.c
    nanostack/source/6LoWPAN/ws/ws_pae_controller.c
    nanostack/source/6LoWPAN/ws/ws_pae_key_storage.c
    nanostack/source/6LoWPAN/ws/ws_pae_lib.c
    nanostack/source/6LoWPAN/ws/ws_pae_nvm_data.c
    nanostack/source/6LoWPAN/ws/ws_pae_supp.c
    nanostack/source/6LoWPAN/ws/ws_pae_time.c
    nanostack/source/6LoWPAN/ws/ws_pae_timers.c
    nanostack/source/6LoWPAN/ws/ws_stats.c
    nanostack/source/6LoWPAN/ws/ws_test_api.c
)
TARGET_INCLUDE_DIRECTORIES(wisun-host PRIVATE
    mbedtls/
    mbedtls/include/
    mbed-trace/
    mbed-client-randlib/mbed-client-randlib/
    mbed-client-libservice/mbed-client-libservice/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)
