/*
 * Copyright (c) 2013-2021, Pelion and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 *
 * \file mac_mlme.c
 * \brief MLME API for MAC control
 *
 *  MLME API for MAC certification.
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "common/hal_interrupt.h"
#include "common/bits.h"
#include "common/rand.h"
#include "common/log_legacy.h"
#include "stack-services/common_functions.h"
#include "stack-scheduler/eventOS_event.h"
#include "stack-scheduler/eventOS_scheduler.h"
#include "stack/mac/sw_mac.h"
#include "stack/mac/mlme.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/mac_filter_api.h"
#include "stack/mac/fhss_api.h"

#include "os_timer.h"
#include "mac/rf_driver_storage.h"
#include "mac/ieee802154/sw_mac_internal.h"
#include "mac/ieee802154/mac_defines.h"
#include "mac/ieee802154/mac_header_helper_functions.h"
#include "mac/ieee802154/mac_indirect_data.h"
#include "mac/ieee802154/mac_security_mib.h"
#include "mac/ieee802154/mac_timer.h"
#include "mac/ieee802154/mac_pd_sap.h"
#include "mac/ieee802154/mac_mcps_sap.h"
#include "mac/ieee802154/mac_cca_threshold.h"

#include "mac/ieee802154/mac_mlme.h"

#define TRACE_GROUP "mlme"

#define MAC_ACK_WAIT_DURATION   90

static int8_t mac_mlme_rf_disable(struct protocol_interface_rf_mac_setup *rf_mac_setup);
static int8_t mac_mlme_rf_receiver_enable(struct protocol_interface_rf_mac_setup *rf_mac_setup);

static void mac_mlme_write_mac16(protocol_interface_rf_mac_setup_s *rf_setup, uint8_t *addrPtr);
static void mac_mlme_write_mac64(struct protocol_interface_rf_mac_setup *rf_setup, uint8_t *addrPtr);
static void mac_mlme_timers_disable(protocol_interface_rf_mac_setup_s *rf_ptr);
static int8_t mac_mlme_set_panid(struct protocol_interface_rf_mac_setup *rf_setup, uint16_t pan_id);
static int8_t mac_mlme_set_mac16(struct protocol_interface_rf_mac_setup *rf_setup, uint16_t mac16);
static int8_t mac_mlme_rf_channel_set(struct protocol_interface_rf_mac_setup *rf_setup, uint8_t new_channel);
static void mac_mlme_timer_cb(int timer_id, uint16_t slots);
static void mac_mlme_start_confirm_handler(protocol_interface_rf_mac_setup_s *rf_ptr, const mlme_start_conf_t *conf);
static int mac_mlme_set_symbol_rate(protocol_interface_rf_mac_setup_s *rf_mac_setup);
static int mac_mlme_allocate_tx_buffers(protocol_interface_rf_mac_setup_s *rf_mac_setup, arm_device_driver_list_s *dev_driver, uint16_t mtu_size);

uint16_t mlme_scan_analyze_next_channel(channel_list_t *mac_channel_list, bool clear_channel)
{
    int chanmax;

    if (mac_channel_list->channel_page == CHANNEL_PAGE_9 ||
        mac_channel_list->channel_page == CHANNEL_PAGE_10)
        chanmax = 256;
    else
        chanmax = 32;

    for (int i = mac_channel_list->next_channel_number; i < chanmax; i++) {
        if (bittest(mac_channel_list->channel_mask, i)) {
            if (clear_channel) {
                bitclr(mac_channel_list->channel_mask, i);
                mac_channel_list->next_channel_number = i + 1;
            }
            return i;
        }
    }
    return 0xffff;
}

static void mac_mlme_start_request(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    mac_pre_build_frame_t *buf;
    platform_enter_critical();

    mac_mlme_rf_disable(rf_mac_setup);
    buf = rf_mac_setup->active_pd_data_request;
    rf_mac_setup->active_pd_data_request = NULL;
    mac_mlme_mac_radio_enable(rf_mac_setup);
    rf_mac_setup->macUpState = true;
    if (buf) {
        // Active packet is pushed back to queue and statistics will be cleared. They need to be updated here.
        sw_mac_stats_update(rf_mac_setup, STAT_MAC_TX_CCA_ATT, rf_mac_setup->mac_tx_status.cca_cnt);
        sw_mac_stats_update(rf_mac_setup, STAT_MAC_TX_RETRY, rf_mac_setup->mac_tx_status.retry);
        mcps_sap_pd_req_queue_write(rf_mac_setup, buf);
    }
    platform_exit_critical();
}

int8_t mac_mlme_start_req(const mlme_start_t *s, struct protocol_interface_rf_mac_setup *rf_mac_setup)
{
    if (!s || !rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return -1;
    }

    tr_debug("MAC: Start network %u channel %x panid", s->LogicalChannel, s->PANId);
    mac_mlme_set_panid(rf_mac_setup, s->PANId);

    // Synchronize FHSS
    if (rf_mac_setup->fhss_api) {
        rf_mac_setup->mac_channel = rf_mac_setup->fhss_api->synch_state_set(rf_mac_setup->fhss_api, FHSS_SYNCHRONIZED, s->PANId);
    } else {
        rf_mac_setup->mac_channel = s->LogicalChannel;
    }

    mac_mlme_start_request(rf_mac_setup);
    if (s->PANCoordinator) {
        //tr_debug("Cordinator");
        rf_mac_setup->macCapCordinator = true;
        rf_mac_setup->macCapRxOnIdle = true;
    } else {
        rf_mac_setup->macCapCordinator = false;
    }

    if (s->BatteryLifeExtension) {
        rf_mac_setup->macCapBatteryPowered = true;
    } else {
        rf_mac_setup->macCapBatteryPowered = false;
    }
    mlme_start_conf_t conf;
    conf.status = MLME_SUCCESS;
    mac_mlme_start_confirm_handler(rf_mac_setup, &conf);
    return 0;
}

int8_t mac_mlme_reset(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_reset_t *reset)
{
    if (!reset || !rf_mac_setup) {
        return -1;
    }

    // Stop FHSS
    if (rf_mac_setup->fhss_api) {
        rf_mac_setup->fhss_api->synch_state_set(rf_mac_setup->fhss_api, FHSS_UNSYNCHRONIZED, 0);
    }

    mac_mlme_timers_disable(rf_mac_setup);
    mac_mlme_mac_radio_disabled(rf_mac_setup);
    mac_mlme_set_active_state(rf_mac_setup, false);
    mac_mcps_buffer_queue_free(rf_mac_setup);
    rf_mac_setup->macWaitingData = false;
    rf_mac_setup->macDataPollReq = false;
    rf_mac_setup->macRxDataAtPoll = false;
    rf_mac_setup->macTxProcessActive = false;
    rf_mac_setup->mac_ack_tx_active = false;
    //Clean MAC
    if (reset->SetDefaultPIB) {
        tr_debug("Reset MAC PIB");
        rf_mac_setup->mac_short_address = 0xffff;
        rf_mac_setup->pan_id = 0xffff;
        rf_mac_setup->macCapRxOnIdle = true;
        rf_mac_setup->mac_security_enabled = false;
        rf_mac_setup->macCapCordinator = false;
        rf_mac_setup->mac_mlme_retry_max = MAC_DEFAULT_MAX_FRAME_RETRIES;
    }

    return 0;
}


static int8_t mac_mlme_boolean_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, mlme_attr_e attribute, bool value)
{
    switch (attribute) {
        case macSecurityEnabled:
            rf_mac_setup->mac_security_enabled = value;
            break;

        case macRxOnWhenIdle:
            rf_mac_setup->macCapRxOnIdle = value;
            break;

        case macEdfeForceStop:
            return mac_data_edfe_force_stop(rf_mac_setup);

        case macAcceptByPassUnknowDevice:
            rf_mac_setup->mac_security_bypass_unknow_device = value;
            break;

        default:
            return -1;
    }
    return 0;
}

static int8_t mac_mlme_16bit_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, mlme_attr_e attribute, uint16_t value)
{
    switch (attribute) {
        case macCoordShortAddress:
            rf_mac_setup->coord_short_address = value;
            break;

        case macPANId:
            mac_mlme_set_panid(rf_mac_setup, value);
            break;

        case macShortAddress:
            mac_mlme_set_mac16(rf_mac_setup, value);
            break;

        default:
            return -1;
    }
    return 0;
}

static int8_t mac_mlme_8bit_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, mlme_attr_e attribute, uint8_t value)
{
    switch (attribute) {
        case phyCurrentChannel:
            mac_mlme_rf_channel_set(rf_mac_setup, value);
            break;
        case macAutoRequestKeyIndex:
            rf_mac_setup->mac_auto_request.KeyIndex = value;
            break;

        case macAutoRequestKeyIdMode:
            rf_mac_setup->mac_auto_request.KeyIdMode = value;
            break;

        case macAutoRequestSecurityLevel:
            rf_mac_setup->mac_auto_request.SecurityLevel = value;
            break;
        case macMaxFrameRetries:
            if (value > 7) {
                return -1;
            }
            rf_mac_setup->mac_mlme_retry_max = value;
            break;

        case macMinBE:
            if (value < rf_mac_setup->macMaxBE) {
                rf_mac_setup->macMinBE = value;
            }
            break;

        case macMaxBE:
            if (value > 8 || value < 1) {
                return -1;
            }
            rf_mac_setup->macMaxBE = value;
            break;

        case macMaxCSMABackoffs:
            if (value > 8) {
                return -1;
            }
            rf_mac_setup->macMaxCSMABackoffs = value;
            break;

        default:
            return -1;
    }
    return 0;
}

static int8_t mac_mlme_32bit_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, mlme_attr_e attribute, uint8_t index, uint32_t value)
{

    switch (attribute) {
        case macFrameCounter:
            if (rf_mac_setup->secFrameCounterPerKey) {
                mlme_key_descriptor_t *key_desc = mac_sec_key_description_get_by_attribute(rf_mac_setup, index);
                if (!key_desc) {
                    return -1;
                }
                mac_sec_mib_key_outgoing_frame_counter_set(rf_mac_setup, key_desc, value);
            } else {
                mac_sec_mib_key_outgoing_frame_counter_set(rf_mac_setup, NULL, value);
            }

            break;

        default:
            return -1;
    }
    return 0;
}

void mac_extended_mac_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, const uint8_t *mac64)
{
    if (!mac64 || !rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return;
    }
    phy_device_driver_s *dev_driver = rf_mac_setup->dev_driver->phy_driver;
    memcpy(rf_mac_setup->mac64, mac64, 8); //This should be random
    if (dev_driver->address_write) {
        dev_driver->address_write(PHY_MAC_64BIT, rf_mac_setup->mac64);
    }
}

static uint32_t mac_calc_ack_wait_duration(protocol_interface_rf_mac_setup_s *rf_mac_setup, uint16_t symbols)
{
    uint32_t AckWaitDuration_us = 0;
    if (rf_mac_setup->rf_csma_extension_supported) {
        AckWaitDuration_us = (symbols * rf_mac_setup->symbol_time_ns) / 1000;
    }
    return AckWaitDuration_us;
}

static int8_t mac_mlme_set_ack_wait_duration(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    uint16_t symbols = common_read_16_bit_inverse((uint8_t *)set_req->value_pointer);
    uint32_t ack_wait_time_us = mac_calc_ack_wait_duration(rf_mac_setup, symbols);
    if (ack_wait_time_us < 50) {
        return -1;
    }
    // MAC timer uses 50us resolution
    rf_mac_setup->mac_ack_wait_duration = ack_wait_time_us / 50;
    tr_debug("Set macAckWaitDuration: %uus", rf_mac_setup->mac_ack_wait_duration * 50);

    return 0;
}

static int8_t mac_mlme_device_description_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{

    if (set_req->value_size != sizeof(mlme_device_descriptor_t)) {
        return -1;
    }
    return mac_sec_mib_device_description_set(set_req->attr_index, (mlme_device_descriptor_t *) set_req->value_pointer, rf_mac_setup);
}

static int8_t mac_mlme_key_description_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    if (set_req->value_size != sizeof(mlme_key_descriptor_entry_t)) {
        return -1;
    }

    return mac_sec_mib_key_description_set(set_req->attr_index, (mlme_key_descriptor_entry_t *) set_req->value_pointer, rf_mac_setup);
}

static int8_t mac_mlme_default_key_source_set(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    if (set_req->value_size != 8) {
        return -1;
    }
    if (set_req->attr == macDefaultKeySource) {
        memcpy(rf_mac_setup->mac_default_key_source, (uint8_t *)set_req->value_pointer, 8);
    } else {
        memcpy(rf_mac_setup->mac_auto_request.Keysource, (uint8_t *)set_req->value_pointer, 8);
    }
    return 0;
}

static int8_t mac_mlme_handle_set_values(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    if (set_req->value_size == 1) {
        const bool *pbool = set_req->value_pointer;
        //Check first boolean
        if (mac_mlme_boolean_set(rf_mac_setup, set_req->attr, *pbool) == 0) {
            return 0;
        }
        const uint8_t *pu8 = set_req->value_pointer;
        return mac_mlme_8bit_set(rf_mac_setup, set_req->attr, *pu8);

    } else if (set_req->value_size == 2) {
        const uint16_t *pu16 = set_req->value_pointer;
        return mac_mlme_16bit_set(rf_mac_setup, set_req->attr, *pu16);
    } else if (set_req->value_size == 4) {
        const uint32_t *pu32 = set_req->value_pointer;
        return mac_mlme_32bit_set(rf_mac_setup, set_req->attr, set_req->attr_index, *pu32);
    }
    return -1;
}

static int8_t mac_mlme_set_data_request_restart_config(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    mlme_request_restart_config_t request_restart_config;
    memcpy(&request_restart_config, set_req->value_pointer, sizeof(mlme_request_restart_config_t));
    rf_mac_setup->cca_failure_restart_max = request_restart_config.cca_failure_restart_max;
    rf_mac_setup->tx_failure_restart_max = request_restart_config.tx_failure_restart_max;
    rf_mac_setup->blacklist_min_ms = request_restart_config.blacklist_min_ms;
    rf_mac_setup->blacklist_max_ms = request_restart_config.blacklist_max_ms;
    tr_debug("Request restart config: CCA %u, TX %u, min %u, max %u", rf_mac_setup->cca_failure_restart_max, rf_mac_setup->tx_failure_restart_max, rf_mac_setup->blacklist_min_ms, rf_mac_setup->blacklist_max_ms);
    return 0;
}

static int8_t mac_mlme_filter_start(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    mlme_request_mac_filter_start_t *p = (mlme_request_mac_filter_start_t *)set_req->value_pointer;
    return mac_filter_start(rf_mac_setup->mac_interface_id, p->lqi_m, p->lqi_add, p->dbm_m, p->dbm_add);
}

static int8_t mac_mlme_filter_clear(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    return mac_filter_clear(rf_mac_setup->mac_interface_id);
}

static int8_t mac_mlme_filter_add_long(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    mlme_request_mac_filter_add_long_t *p = (mlme_request_mac_filter_add_long_t *)set_req->value_pointer;
    return mac_filter_add_long(rf_mac_setup->mac_interface_id, p->mac64, p->lqi_m, p->lqi_add, p->dbm_m, p->dbm_add);
}

static int8_t mac_mlme_filter_stop(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    mac_filter_stop(rf_mac_setup->mac_interface_id);
    return 0;
}

int8_t mac_mlme_set_req(protocol_interface_rf_mac_setup_s *rf_mac_setup, const mlme_set_t *set_req)
{
    if (!set_req || !rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return -1;
    }
    uint8_t *pu8 = NULL;
    switch (set_req->attr) {
        case macAckWaitDuration:
            return mac_mlme_set_ack_wait_duration(rf_mac_setup, set_req);
        case macDeviceTable:
            return mac_mlme_device_description_set(rf_mac_setup, set_req);
        case macKeyTable:
            return mac_mlme_key_description_set(rf_mac_setup, set_req);
        case macDefaultKeySource:
        case macAutoRequestKeySource:
            return mac_mlme_default_key_source_set(rf_mac_setup, set_req);
        case macCoordExtendedAddress:
            if (set_req->value_size == 8) {
                memcpy(rf_mac_setup->coord_long_address, set_req->value_pointer, 8);
            }
            return 0;
        case macSetDataWhitening:
            pu8 = (uint8_t *) set_req->value_pointer;
            rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_DATA_WHITENING, pu8);
            tr_debug("%s data whitening", *pu8 == (bool) true ? "Enable" : "Disable");
            return 0;
        case macCCAThresholdStart:
            pu8 = (uint8_t *) set_req->value_pointer;
            mac_cca_thr_init(rf_mac_setup, *pu8, *((int8_t *)pu8 + 1), *((int8_t *)pu8 + 2), *((int8_t *)pu8 + 3));
            return 0;
        case mac802_15_4Mode:
            pu8 = (uint8_t *) set_req->value_pointer;
            if (rf_mac_setup->current_mac_mode == *pu8) {
                return -1;
            }
            rf_mac_setup->current_mac_mode = *pu8;
            rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_802_15_4_MODE, pu8);
            uint16_t new_mtu_size = MAC_IEEE_802_15_4_MAX_PHY_PACKET_SIZE;
            if (*pu8 == IEEE_802_15_4G_2012) {
                new_mtu_size = MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE;
            }
            mac_api_t *mac_api = get_sw_mac_api(rf_mac_setup);
            if (rf_mac_setup->dev_driver->phy_driver->phy_MTU > new_mtu_size) {
                mac_api->mtu = rf_mac_setup->phy_mtu_size = new_mtu_size;
            } else {
                mac_api->mtu = rf_mac_setup->phy_mtu_size = rf_mac_setup->dev_driver->phy_driver->phy_MTU;
            }
            if (mac_mlme_allocate_tx_buffers(rf_mac_setup, rf_mac_setup->dev_driver, rf_mac_setup->phy_mtu_size)) {
                tr_error("Failed to reallocate TX buffers");
                return -1;
            }
            tr_debug("Set MAC mode to %s, MTU size: %u", *pu8 == IEEE_802_15_4G_2012 ? "IEEE 802.15.4G-2012" : "IEEE 802.15.4-2011", rf_mac_setup->phy_mtu_size);
            return 0;
        case macTXPower:
            pu8 = (uint8_t *) set_req->value_pointer;
            rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_TX_POWER, pu8);
            tr_debug("Set TX output power to %u%%", *pu8);
            return 0;
        case macCCAThreshold:
            pu8 = (uint8_t *) set_req->value_pointer;
            rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_CCA_THRESHOLD, pu8);
            tr_info("Set CCA threshold to %u%%", *pu8);
            return 0;
        case macMultiCSMAParameters:
            return 0;
        case macRequestRestart:
            return mac_mlme_set_data_request_restart_config(rf_mac_setup, set_req);
        case macFilterStart:
            return mac_mlme_filter_start(rf_mac_setup, set_req);
        case macFilterClear:
            return mac_mlme_filter_clear(rf_mac_setup);
        case macFilterAddLong:
            return mac_mlme_filter_add_long(rf_mac_setup, set_req);
        case macFilterStop:
            return mac_mlme_filter_stop(rf_mac_setup);
        case macRfConfiguration:
            rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_RF_CONFIGURATION, (uint8_t *) set_req->value_pointer);
            mac_mlme_set_symbol_rate(rf_mac_setup);
            phy_rf_channel_configuration_t *config_params = (phy_rf_channel_configuration_t *)set_req->value_pointer;
            rf_mac_setup->datarate = config_params->datarate;
            tr_info("New RF config:");
            tr_info("  Frequency(ch0): %"PRIu32"Hz", config_params->channel_0_center_frequency);
            tr_info("  Channel spacing: %"PRIu32"Hz", config_params->channel_spacing);
            tr_info("  Datarate: %"PRIu32"bps", config_params->datarate);
            tr_info("  Number of channels: %u", config_params->number_of_channels);
            tr_info("  Modulation: %u", config_params->modulation);
            tr_info("  Modulation index: %u", config_params->modulation_index);
            tr_info("  FEC: %u", config_params->fec);
            tr_info("  OFDM MCS: %u", config_params->ofdm_mcs);
            tr_info("  OFDM option: %u", config_params->ofdm_option);
            return 0;
        default:
            return mac_mlme_handle_set_values(rf_mac_setup, set_req);
    }
}

int8_t mac_mlme_get_req(struct protocol_interface_rf_mac_setup *rf_mac_setup, mlme_get_conf_t *get_req)
{
    if (!get_req || !rf_mac_setup) {
        return -1;
    }
    mac_cca_threshold_s *cca_thr_table = NULL;
    switch (get_req->attr) {
        case macDeviceTable:
            get_req->value_pointer = mac_sec_mib_device_description_get_attribute_index(rf_mac_setup, get_req->attr_index);
            if (get_req->value_pointer) {
                get_req->value_size = sizeof(mlme_device_descriptor_t);
            } else {
                get_req->status = MLME_INVALID_INDEX;
            }
            break;

        case macMaxFrameRetries:
            get_req->value_pointer = &rf_mac_setup->mac_mlme_retry_max;
            get_req->value_size = 1;
            break;

        case macFrameCounter:
            if (rf_mac_setup->secFrameCounterPerKey) {
                mlme_key_descriptor_t *key_desc = mac_sec_key_description_get_by_attribute(rf_mac_setup, get_req->attr_index);
                if (!key_desc) {
                    return -1;
                }
                get_req->value_pointer = &key_desc->KeyFrameCounter;
            } else {
                get_req->value_pointer = &rf_mac_setup->security_frame_counter;
            }

            get_req->value_size = 4;
            break;

        case macCCAThreshold:
            cca_thr_table = mac_get_cca_threshold_table(rf_mac_setup);
            get_req->value_size = cca_thr_table->number_of_channels;
            get_req->value_pointer = cca_thr_table->ch_thresholds;
            break;

        case macRxSensitivity:
            // Value is hardcoed in sl_wsrcp_mac.c
            get_req->value_pointer = NULL;
            get_req->value_size = 0;
            break;

        default:
            get_req->status = MLME_UNSUPPORTED_ATTRIBUTE;
            break;

    }
    return 0;
}

void mac_frame_src_address_set_from_interface(uint8_t SrcAddrMode, protocol_interface_rf_mac_setup_s *rf_ptr, uint8_t *addressPtr)
{
    if (!rf_ptr) {
        return;
    }
    if (SrcAddrMode == MAC_ADDR_MODE_16_BIT) {
        mac_mlme_write_mac16(rf_ptr, addressPtr);
    } else if (SrcAddrMode == MAC_ADDR_MODE_64_BIT) {
        mac_mlme_write_mac64(rf_ptr, addressPtr);
    }
}

static void mac_mlme_timers_disable(protocol_interface_rf_mac_setup_s *rf_ptr)
{
    platform_enter_critical();
    if (rf_ptr->mac_mlme_event != ARM_NWK_MAC_MLME_IDLE) {
        os_timer_stop(rf_ptr->mlme_timer_id);
        rf_ptr->mac_mlme_event = ARM_NWK_MAC_MLME_IDLE;
    }
    timer_mac_stop(rf_ptr);
    platform_exit_critical();
}

void mac_mlme_event_cb(void *mac_ptr)
{
    protocol_interface_rf_mac_setup_s *rf_mac_setup = (protocol_interface_rf_mac_setup_s *) mac_ptr;
    if (!rf_mac_setup) {
        return;
    }
    arm_nwk_mlme_event_type_e event_type;
    event_type = rf_mac_setup->mac_mlme_event;
    rf_mac_setup->mac_mlme_event = ARM_NWK_MAC_MLME_IDLE;
    switch (event_type) {
        case ARM_NWK_MAC_MLME_INDIRECT_DATA_POLL:
            tr_debug("Data poll data wait TO");
            mac_mlme_poll_process_confirm(rf_mac_setup, MLME_NO_DATA);
            break;

        case ARM_NWK_MAC_MLME_INDIRECT_DATA_POLL_AFTER_DATA:
            mac_mlme_poll_process_confirm(rf_mac_setup, MLME_SUCCESS);
            break;

        default:
            break;
    }
}

static void mac_mcps_timer_cb(int timer_id, uint16_t slots)
{

    protocol_interface_rf_mac_setup_s *rf_ptr = get_sw_mac_ptr_by_timer(timer_id, ARM_MCPS_TIMER);
    if (!rf_ptr || !rf_ptr->dev_driver || !rf_ptr->dev_driver->phy_driver) {
        return;
    }
    rf_ptr->mac_mcps_timer_event.event_data = slots;
    eventOS_event_send(&rf_ptr->mac_mcps_timer_event);

}


static void mac_mlme_timer_cb(int timer_id, uint16_t slots)
{
    protocol_interface_rf_mac_setup_s *rf_ptr = get_sw_mac_ptr_by_timer(timer_id, ARM_NWK_MLME_TIMER);
    if (!rf_ptr || !rf_ptr->dev_driver || !rf_ptr->dev_driver->phy_driver) {
        return;
    }

    if (rf_ptr->mlme_tick_count == 0) {
        if (rf_ptr->mac_mlme_event != ARM_NWK_MAC_MLME_IDLE)
            mac_generic_event_trig(MAC_MLME_EVENT_HANDLER, rf_ptr, true);
    } else {
        rf_ptr->mlme_tick_count--;
        os_timer_start(timer_id, slots);
    }
}

void mac_mlme_set_active_state(protocol_interface_rf_mac_setup_s *entry, bool new_state)
{
    if (entry) {
        entry->macUpState = new_state;
    }
}

void mac_mlme_data_base_deallocate(struct protocol_interface_rf_mac_setup *rf_mac)
{
    if (rf_mac) {
        if (rf_mac->dev_driver) {
            rf_mac->dev_driver->phy_sap_identifier = NULL;
        }

        os_timer_unregister(rf_mac->mlme_timer_id);
        os_timer_unregister(rf_mac->mac_timer_id);
        os_timer_unregister(rf_mac->mac_mcps_timer);

        free(rf_mac->dev_driver_tx_buffer.buf);
        free(rf_mac->dev_driver_tx_buffer.enhanced_ack_buf);

        mac_sec_mib_deinit(rf_mac);
        mac_cca_thr_deinit(rf_mac);
        free(rf_mac);
    }
}

static uint8_t mac_backoff_ticks_calc(phy_device_driver_s *phy_driver)
{
    //Calculate 20 symbol time which is typically 10 bytes
    const phy_device_channel_page_s *phy_channel_pages = phy_driver->phy_channel_pages;
    uint32_t datarate = dev_get_phy_datarate(phy_driver, phy_channel_pages->channel_page);
    if (datarate == 0) {
        datarate = 250000;
    }
    //How many 10us ticks backoff period is, assuming 4 bits per symbol (O-QPSK)
    unsigned int ticks = (2000000 / (datarate / 4));
    if (ticks > 255) {
        ticks = 255;
        tr_warn("Backoff period too slow");
    }
    return (uint8_t) ticks;
}

static int mac_mlme_set_symbol_rate(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    if (rf_mac_setup->rf_csma_extension_supported) {
        rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_GET_SYMBOLS_PER_SECOND, (uint8_t *) &rf_mac_setup->symbol_rate);
        rf_mac_setup->symbol_time_ns = 1000000000 / rf_mac_setup->symbol_rate;
        tr_debug("SW-MAC driver support rf extension %"PRIu32" symbol/seconds  %"PRIu32" ns symbol time length", rf_mac_setup->symbol_rate, rf_mac_setup->symbol_time_ns);
        return 0;
    }
    return -1;
}

static int mac_mlme_allocate_tx_buffers(protocol_interface_rf_mac_setup_s *rf_mac_setup, arm_device_driver_list_s *dev_driver, uint16_t mtu_size)
{
    free(rf_mac_setup->dev_driver_tx_buffer.buf);
    uint16_t total_length = 0;
    //Allocate tx buffer by given MTU + header + tail
    total_length = mtu_size;
    total_length += (dev_driver->phy_driver->phy_header_length + dev_driver->phy_driver->phy_tail_length);
    rf_mac_setup->dev_driver_tx_buffer.buf = malloc(total_length);
    if (!rf_mac_setup->dev_driver_tx_buffer.buf) {
        return -1;
    }
    return 0;
}

protocol_interface_rf_mac_setup_s *mac_mlme_data_base_allocate(uint8_t *mac64, arm_device_driver_list_s *dev_driver, mac_description_storage_size_t *storage_sizes, uint16_t mtu_size)
{
    //allocate security
    if (!dev_driver || !mac64 || !dev_driver->phy_driver || !storage_sizes) {
        return NULL;
    }

    protocol_interface_rf_mac_setup_s *entry = malloc(sizeof(protocol_interface_rf_mac_setup_s));
    if (!entry) {
        return NULL;
    }
    //Init everything for 0, NULL or false
    memset(entry, 0, sizeof(protocol_interface_rf_mac_setup_s));
    entry->ifs_timer_id = -1;
    entry->cca_timer_id = -1;
    entry->mlme_timer_id = -1;
    entry->mac_timer_id = -1;
    entry->bc_timer_id = -1;
    entry->mac_interface_id = -1;
    entry->dev_driver = dev_driver;
    entry->aUnitBackoffPeriod = 20; //This can be different in some Platform 20 comes from 12-symbol turnaround and 8 symbol CCA read
    entry->mac_channel_list.channel_page = CHANNEL_PAGE_UNDEFINED;

    if (mac_sec_mib_init(entry, storage_sizes) != 0) {
        mac_mlme_data_base_deallocate(entry);
        return NULL;
    }

    if (!dev_driver->phy_driver->phy_MTU) {
        mac_mlme_data_base_deallocate(entry);
        return NULL;
    }
    entry->phy_mtu_size = mtu_size;

    if (mac_mlme_allocate_tx_buffers(entry, dev_driver, mtu_size)) {
        mac_mlme_data_base_deallocate(entry);
        return NULL;
    }

    entry->mac_tasklet_id = mac_mcps_sap_tasklet_init();
    if (entry->mac_tasklet_id < 0) {
        mac_mlme_data_base_deallocate(entry);
        return NULL;
    }

    entry->mlme_timer_id = os_timer_register(mac_mlme_timer_cb);
    entry->mac_timer_id = os_timer_register(timer_mac_interrupt);
    entry->mac_mcps_timer = os_timer_register(mac_mcps_timer_cb);
    if (entry->mlme_timer_id == -1 || entry->mac_timer_id == -1 || entry->mac_mcps_timer == -1) {
        mac_mlme_data_base_deallocate(entry);
        return NULL;
    }
    entry->macCapRxOnIdle = true;
    entry->macCapSecrutityCapability = true;
    entry->pan_id = entry->mac_short_address = 0xffff;
    mac_extended_mac_set(entry, mac64);
    entry->mac_ack_wait_duration = MAC_ACK_WAIT_DURATION;
    entry->mac_mlme_retry_max = MAC_DEFAULT_MAX_FRAME_RETRIES;
    memset(entry->mac_default_key_source, 0xff, 8);
    memset(entry->mac_auto_request.Keysource, 0xff, 8);
    entry->mac_auto_request.SecurityLevel = 6;
    entry->mac_auto_request.KeyIndex = 0xff;
    mac_pd_sap_rf_low_level_function_set(entry, entry->dev_driver);
    entry->mac_sequence = rand_get_8bit();
    entry->mac_bea_sequence = rand_get_8bit();
    entry->fhss_api = NULL;
    entry->macMinBE = 3;
    entry->macMaxBE = 5;
    entry->macMaxCSMABackoffs = MAC_CCA_MAX;
    entry->mac_mcps_timer_event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    entry->mac_mcps_timer_event.event_type = MAC_MCPS_INDIRECT_TIMER_CB;
    entry->mac_mcps_timer_event.data_ptr = entry;
    entry->mac_mcps_timer_event.receiver = entry->mac_tasklet_id;
    entry->mac_mcps_timer_event.sender = 0;
    entry->mac_mcps_timer_event.event_id = 0;
    bool rf_support = false;
    dev_driver->phy_driver->extension(PHY_EXTENSION_DYNAMIC_RF_SUPPORTED, (uint8_t *)&rf_support);
    entry->rf_csma_extension_supported = rf_support;
    dev_driver->phy_driver->extension(PHY_EXTENSION_FILTERING_SUPPORT, (uint8_t *)&entry->mac_frame_filters);
    if (entry->mac_frame_filters & (1u << MAC_FRAME_VERSION_2)) {
        tr_debug("PHY supports 802.15.4-2015 frame filtering");
    }
    mac_mlme_set_symbol_rate(entry);

    //How many 10us ticks backoff period is for waiting 20symbols which is typically 10 bytes time
    entry->backoff_period_in_10us = mac_backoff_ticks_calc(dev_driver->phy_driver);
    return entry;
}

uint8_t mac_mlme_set_new_sqn(protocol_interface_rf_mac_setup_s *rf_setup)
{
    uint8_t ret_val = 0;

    if (rf_setup) {
        rf_setup->mac_sequence++;
        ret_val = rf_setup->mac_sequence;
    }
    return ret_val;
}

static int8_t mac_mlme_set_panid(struct protocol_interface_rf_mac_setup *rf_setup, uint16_t pan_id)
{
    phy_device_driver_s *dev_driver = rf_setup->dev_driver->phy_driver;
    if (!dev_driver->address_write) {
        if (dev_driver->link_type == PHY_LINK_TUN) {
            rf_setup->pan_id = pan_id;
            return 0;
        }
        return -1;
    }

    uint8_t temp_8[2];
    rf_setup->pan_id = pan_id;
    common_write_16_bit(pan_id, temp_8);

    return dev_driver->address_write(PHY_MAC_PANID, temp_8);
}

static void mac_mlme_write_mac16_to_phy(phy_device_driver_s *dev_driver, uint16_t mac16)
{
    uint8_t temp[2];
    common_write_16_bit(mac16, temp);
    if (dev_driver->address_write) {
        dev_driver->address_write(PHY_MAC_16BIT, temp);
    }
}

static int8_t mac_mlme_set_mac16(struct protocol_interface_rf_mac_setup *rf_setup, uint16_t mac16)
{
    int8_t ret_val = -1;
    if (rf_setup) {

        rf_setup->mac_short_address = mac16;
        //SET RF 16-bit
        if (mac16 > 0xfffd) {
            rf_setup->shortAdressValid = false;
        } else {
            rf_setup->shortAdressValid = true;
        }
        mac_mlme_write_mac16_to_phy(rf_setup->dev_driver->phy_driver, mac16);
        ret_val = 0;
    }
    return ret_val;
}

static void mac_mlme_write_mac64(protocol_interface_rf_mac_setup_s *rf_setup, uint8_t *addrPtr)
{
    memcpy(addrPtr, rf_setup->mac64, 8);
}

static void mac_mlme_write_mac16(protocol_interface_rf_mac_setup_s *rf_setup, uint8_t *addrPtr)
{
    common_write_16_bit(rf_setup->mac_short_address, addrPtr);
}

uint16_t mac_mlme_get_panid(protocol_interface_rf_mac_setup_s *rf_setup)
{
    uint16_t panId = 0xffff;
    if (rf_setup) {
        panId = rf_setup->pan_id;
    }
    return panId;
}

static void mac_mlme_start_confirm_handler(protocol_interface_rf_mac_setup_s *rf_ptr, const mlme_start_conf_t *conf)
{
    if (get_sw_mac_api(rf_ptr)) {
        if (get_sw_mac_api(rf_ptr)->mlme_conf_cb) {
            get_sw_mac_api(rf_ptr)->mlme_conf_cb(get_sw_mac_api(rf_ptr), MLME_START, conf);
        }
    }
}

void mac_mlme_mac_radio_disabled(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    if (!rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return;
    }
    platform_enter_critical();
    timer_mac_stop(rf_mac_setup);
    mac_mlme_rf_disable(rf_mac_setup);
    platform_exit_critical();
}

void mac_mlme_mac_radio_enable(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    if (!rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return;
    }
    platform_enter_critical();
    mac_mlme_rf_receiver_enable(rf_mac_setup);
    platform_exit_critical();
}

static int8_t mac_mlme_rf_disable(protocol_interface_rf_mac_setup_s *rf_mac_setup)
{
    int8_t ret_val = 0;
    phy_device_driver_s *dev_driver = rf_mac_setup->dev_driver->phy_driver;
    if (!dev_driver->state_control) {
        if (dev_driver->link_type == PHY_LINK_TUN) {
            rf_mac_setup->macRfRadioOn = false;
            rf_mac_setup->macRfRadioTxActive = false;
            return 0;
        }
        return -1;
    }
    if (rf_mac_setup->macRfRadioOn) {
        ret_val = dev_driver->state_control(PHY_INTERFACE_DOWN, 0);
        rf_mac_setup->macRfRadioOn = false;
        rf_mac_setup->macRfRadioTxActive = false;
    }

    return ret_val;
}

static int8_t mac_mlme_rf_receiver_enable(struct protocol_interface_rf_mac_setup *rf_mac_setup)
{
    int8_t retval;

    phy_device_driver_s *dev_driver = rf_mac_setup->dev_driver->phy_driver;
    if (!dev_driver->state_control) {
        if (dev_driver->link_type == PHY_LINK_TUN) {
            rf_mac_setup->macRfRadioOn = true;
            return 0;
        }
        return -1;
    }

    if (rf_mac_setup->macRfRadioOn) {
        return 0;
    }

    retval = dev_driver->state_control(PHY_INTERFACE_UP, rf_mac_setup->mac_channel);
    rf_mac_setup->macRfRadioOn = true;
    //tr_debug("Enable radio with channel %u", rf_mac_setup->mac_channel);
    return retval;
}

/**
 * Initialize MAC channel selection sequence
 *
 * TODO: initialize channel select sequence
 *       in coordinator mode
 *
 * \param new_channel channel to set
 *
 * \return 0 success
 * \return -1 HW error
 */
static int8_t mac_mlme_rf_channel_set(struct protocol_interface_rf_mac_setup *rf_setup, uint8_t new_channel)
{
    if (new_channel == rf_setup->mac_channel) {
        return 0;
    }
    mac_pre_build_frame_t *buf;

    //Disable always
    mac_mlme_mac_radio_disabled(rf_setup);
    buf = rf_setup->active_pd_data_request;
    rf_setup->active_pd_data_request = NULL;
    //Set Channel
    rf_setup->mac_channel = new_channel;
    //Enable Radio
    mac_mlme_mac_radio_enable(rf_setup);
    if (buf) {
        mcps_sap_pd_req_queue_write(rf_setup, buf);
    }

    return 0;
}

/**
 * MAC channel change
 *
 * \param new_channel channel to set
 *
 * \return 0 success
 * \return -1 error
 */
int8_t mac_mlme_rf_channel_change(protocol_interface_rf_mac_setup_s *rf_mac_setup, uint8_t new_channel)
{
    if (!rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return -1;
    }

    if (!rf_mac_setup->dev_driver->phy_driver->extension) {
        if (rf_mac_setup->dev_driver->phy_driver->link_type == PHY_LINK_TUN) {
            rf_mac_setup->mac_channel = new_channel;
            return 0;
        }
        return -1;
    }
    if (new_channel == rf_mac_setup->mac_channel) {
        return 0;
    }

    platform_enter_critical();
    if (rf_mac_setup->dev_driver->phy_driver->extension(PHY_EXTENSION_SET_CHANNEL, &new_channel) == 0) {
        rf_mac_setup->mac_channel = new_channel;
    }
    platform_exit_critical();
    return 0;
}

void mac_mlme_poll_process_confirm(protocol_interface_rf_mac_setup_s *rf_mac_setup, uint8_t status)
{
    if (!rf_mac_setup || !rf_mac_setup->dev_driver || !rf_mac_setup->dev_driver->phy_driver) {
        return;
    }

    //Free active Data buffer
    if (rf_mac_setup->active_pd_data_request) {
        mcps_sap_prebuild_frame_buffer_free(rf_mac_setup->active_pd_data_request);
        rf_mac_setup->active_pd_data_request = NULL;
    }
    //Disable timer
    rf_mac_setup->macWaitingData = false;
    rf_mac_setup->macDataPollReq = false;
    rf_mac_setup->macRxDataAtPoll = false;

    if (!rf_mac_setup->macCapRxOnIdle) {
        //Disable Radio If we are RX off at idle device
        //tr_debug("disbale by aceptance data");
        if (!rf_mac_setup->macRfRadioTxActive) {
            //Disable radio if no active TX and radio is enabled
            //tr_debug("RF disable");
            mac_mlme_mac_radio_disabled(rf_mac_setup);
        }
    }

    mac_api_t *mac_api = get_sw_mac_api(rf_mac_setup);
    if (mac_api) {
        mlme_poll_conf_t confirm;
        confirm.status = status;
        mac_api->mlme_conf_cb(mac_api, MLME_POLL, &confirm);
    }
    //Trig Packet from queue
    mac_mcps_trig_buffer_from_queue(rf_mac_setup);

}

void mac_mlme_poll_req(protocol_interface_rf_mac_setup_s *cur, const mlme_poll_t *poll_req)
{
    if (!cur || !poll_req) {
        return;
    }
    if (cur->macDataPollReq) {
        tr_debug("Poll Active do not start new");
        return;
    }
    mac_pre_build_frame_t *buf = mcps_sap_prebuild_frame_buffer_get(0);
    if (!buf) {
        tr_debug("No mem for data Req");
        //Confirmation call here
        return;
    }

    buf->fcf_dsn.frametype = FC_CMD_FRAME;
    buf->WaitResponse = true;
    buf->fcf_dsn.ackRequested = true;
    buf->fcf_dsn.intraPan = true;

    buf->DstPANId = poll_req->CoordPANId;
    buf->SrcPANId = poll_req->CoordPANId;
    buf->fcf_dsn.DstAddrMode = poll_req->CoordAddrMode;
    memcpy(buf->DstAddr, poll_req->CoordAddress, 8);

    buf->mac_command_id = MAC_DATA_REQ;
    buf->mac_payload = &buf->mac_command_id;
    buf->mac_payload_length = 1;
    buf->mac_header_length_with_security = 3;

    mac_header_security_parameter_set(&buf->aux_header, &poll_req->Key);

    if (buf->aux_header.securityLevel) {
        buf->fcf_dsn.securityEnabled = true;
        buf->fcf_dsn.frameVersion = MAC_FRAME_VERSION_2006;

    }
    cur->macDataPollReq = true;
    cur->macWaitingData = true;
    cur->macRxDataAtPoll = false;

    buf->security_mic_len = mac_security_mic_length_get(buf->aux_header.securityLevel);
    buf->mac_header_length_with_security += mac_header_security_aux_header_length(buf->aux_header.securityLevel, buf->aux_header.KeyIdMode);

    if (cur->mac_short_address > 0xfffd) {
        buf->fcf_dsn.SrcAddrMode = MAC_ADDR_MODE_64_BIT;
    } else {
        buf->fcf_dsn.SrcAddrMode = MAC_ADDR_MODE_16_BIT;
    }
    mac_frame_src_address_set_from_interface(buf->fcf_dsn.SrcAddrMode, cur, buf->SrcAddr);
    //Check PanID presents at header
    buf->fcf_dsn.DstPanPresents = mac_dst_panid_present(&buf->fcf_dsn);
    buf->fcf_dsn.SrcPanPresents = mac_src_panid_present(&buf->fcf_dsn);
    buf->mac_header_length_with_security += mac_header_address_length(&buf->fcf_dsn);
    buf->priority = MAC_PD_DATA_MEDIUM_PRIORITY;
    mcps_sap_pd_req_queue_write(cur, buf);
}

