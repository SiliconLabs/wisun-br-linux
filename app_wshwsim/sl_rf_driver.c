/*
 * Copyright (c) 2016-2019, Arm Limited and affiliates.
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
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifdef HAVE_LIBPCAP
#  include <pcap/pcap.h>
#endif
#include "common/log_legacy.h"
#include "stack/mac/platform/arm_hal_phy.h"
#include "stack/mac/mlme.h"
#include "stack/mac/mac_api.h"
#include "common/ws_regdb.h"
#include "common/log.h"
#include "common/utils.h"

#include "mac/rf_driver_storage.h"
#include "sl_wsrcp.h"
#include "sl_rf_driver.h"

#define TRACE_GROUP "vrf"

static phy_device_driver_s device_driver;
static uint8_t rf_mac_address[8];
static int8_t rf_driver_id = (-1);
static bool data_request_pending_flag = false;
static uint16_t channel = 0;


/** XXX: dummy values copied from Atmel RF driver */
static const phy_rf_channel_configuration_t phy_2_4ghz = {.channel_0_center_frequency = 2405000000, .channel_spacing = 5000000, .datarate = 250000, .number_of_channels = 16, .modulation = MODULATION_OQPSK};
static const phy_rf_channel_configuration_t phy_subghz = {.channel_0_center_frequency = 868300000, .channel_spacing = 2000000, .datarate = 250000, .number_of_channels = 11, .modulation = MODULATION_OQPSK};

static const phy_rf_channel_configuration_t phy_subghz_8_ch = {.channel_0_center_frequency = 868300000, .channel_spacing = 2000000, .datarate = 250000, .number_of_channels = 8, .modulation = MODULATION_OQPSK};
static const phy_rf_channel_configuration_t phy_subghz_11_ch = {.channel_0_center_frequency = 868300000, .channel_spacing = 2000000, .datarate = 250000, .number_of_channels = 11, .modulation = MODULATION_OQPSK};
static const phy_rf_channel_configuration_t phy_subghz_16_ch = {.channel_0_center_frequency = 868300000, .channel_spacing = 2000000, .datarate = 250000, .number_of_channels = 16, .modulation = MODULATION_OQPSK};
static const phy_rf_channel_configuration_t phy_2_4ghz_14_ch = {.channel_0_center_frequency = 2405000000, .channel_spacing = 1000000, .datarate = 250000, .number_of_channels = 14, .modulation = MODULATION_OQPSK};
static const phy_rf_channel_configuration_t phy_2_4ghz_5_ch = {.channel_0_center_frequency = 2405000000, .channel_spacing = 1000000, .datarate = 250000, .number_of_channels = 5, .modulation = MODULATION_OQPSK}; //For FHSS testing only
static const phy_rf_channel_configuration_t phy_2_4ghz_256_ch = {.channel_0_center_frequency = 2405000000, .channel_spacing = 1000000, .datarate = 250000, .number_of_channels = 256, .modulation = MODULATION_OQPSK}; //For FHSS testing only

static phy_device_channel_page_s phy_channel_pages[] = {
    {CHANNEL_PAGE_0, &phy_2_4ghz}, // this will be modified to contain 11 or 16 channels, depending on radio type
    {CHANNEL_PAGE_1, &phy_subghz_11_ch}, // channel 0&ASK or 1..10&ASK
    {CHANNEL_PAGE_2, &phy_subghz_11_ch}, // 0&O-QPSK, or 1-10&O-QPSK
    // following are based on 202.15.2009 additional channel pages:
    {CHANNEL_PAGE_3, &phy_2_4ghz_14_ch}, // 0.13&CSSS
    {CHANNEL_PAGE_4, &phy_subghz_16_ch}, // 0&UWB, 1-4&UWB or 5-15&UWB
    {CHANNEL_PAGE_5, &phy_subghz_8_ch}, // this would need to be either 0..3&O-QPSK or 4-7&MPSK
    {CHANNEL_PAGE_6, &phy_subghz_11_ch}, // this would need to be either 0..9&BPSK or 1-10&GFSK
    // just for testing fhss
    {CHANNEL_PAGE_9, &phy_2_4ghz_256_ch},
    {CHANNEL_PAGE_10, &phy_2_4ghz_5_ch}, // 5 channels, just as in cmd_network.c
    {CHANNEL_PAGE_0, NULL}
};

static int8_t phy_rf_state_control(phy_interface_state_e new_state, uint8_t channel);
static int8_t phy_rf_tx(uint8_t *data_ptr, uint16_t data_len, uint8_t tx_handle, data_protocol_e protocol);
static int8_t phy_rf_address_write(phy_address_type_e address_type, uint8_t *address_ptr);
static int8_t phy_rf_extension(phy_extension_type_e extension_type, uint8_t *data_ptr);

/**
 * \brief This function is used by the network stack library to set the interface state:
 *
 * \param new_state An interface state: PHY_INTERFACE_RESET, PHY_INTERFACE_DOWN,
 *                  PHY_INTERFACE_UP or PHY_INTERFACE_RX_ENERGY_STATE.
 *
 * \param channel An RF channel that the command applies to.
 *
 * \return 0 State update is OK.
 * \return -1 An unsupported state or a general failure.
 */
static int8_t phy_rf_state_control(phy_interface_state_e new_state, uint8_t channel)
{
    (void)new_state;
    (void)channel;
    return 0;
}

void write_pcap(struct wsmac_ctxt *ctxt, uint8_t *buf, int len)
{
#ifdef HAVE_LIBPCAP
    struct pcap_pkthdr pcap_hdr;

    if (ctxt->pcap_dumper) {
        gettimeofday(&pcap_hdr.ts, NULL);
        pcap_hdr.caplen = len;
        pcap_hdr.len = len;
        pcap_dump((uint8_t *)ctxt->pcap_dumper, &pcap_hdr, buf);
        pcap_dump_flush(ctxt->pcap_dumper);
    }
#endif
}

void rf_rx(struct wsmac_ctxt *ctxt)
{
    uint8_t buf[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    uint8_t hdr[6];
    uint16_t pkt_len;
    int pkt_chan;
    int len;

    len = read(ctxt->rf_fd, hdr, 6);
    FATAL_ON(!len, 2, "RF server has gone");
    FATAL_ON(len < 0, 2, "RF socket: %m");
    if (len != 6 || hdr[0] != 'x' || hdr[1] != 'x') {
        TRACE(TR_RF, " rf drop: chan=%2d/%2d %s", -1, channel,
              tr_bytes(hdr, len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
        return;
    }
    pkt_len = ((uint16_t *)hdr)[1];
    pkt_chan = ((uint16_t *)hdr)[2];
    len = read(ctxt->rf_fd, buf, pkt_len);
    WARN_ON(len != pkt_len);
    TRACE(TR_RF, "   rf rx: chan=%2d/%2d %s (%d bytes)", pkt_chan, channel,
          tr_bytes(buf, len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), pkt_len);
    write_pcap(ctxt, buf, len);
    ctxt->rf_driver->phy_driver->phy_rx_cb(buf, len, 200, 0, ctxt->rcp_driver_id);
}

/**
 * \brief This function is used give driver data to transfer.
 *
 * \param data_ptr A pointer to TX data. The platform driver can use the same pointer, but the
 *                 network stack will free the memory when the device driver implementation
 *                 notifies the stack (using the unique tx_handle) that it is allowed to do so.
 *
 * \param data_len The length of data behind a pointer.
 *
 * \param tx_handle A unique TX handle defined by the network stack.
 *
 * \return 0 TX process start is OK. The library must wait for the TX Done callback
 *           before pushing a new packet.
 * \return 1 TX process is OK at the Ethernet side (fast TX phase).
 *
 * \return -1 PHY is busy.
 *
 */
static int8_t phy_rf_tx(uint8_t *data_ptr, uint16_t data_len, uint8_t tx_handle, data_protocol_e protocol)
{
    uint8_t hdr[6];
    struct wsmac_ctxt *ctxt = &g_ctxt;

    BUG_ON(!data_ptr);

    if (ctxt->rf_frame_cca_progress)
        return -1;

    // Prepend data with a synchronisation marker
    memcpy(hdr + 0, "xx", 2);
    memcpy(hdr + 2, &data_len, 2);
    memcpy(hdr + 4, &channel, 2);
    TRACE(TR_RF, "   rf tx: chan=%2d/%2d %s (%d bytes)", channel, channel,
          tr_bytes(data_ptr, data_len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), data_len);
    write(ctxt->rf_fd, hdr, 6);
    write(ctxt->rf_fd, data_ptr, data_len);
    ctxt->rf_frame_cca_progress = true;
    write_pcap(ctxt, data_ptr, data_len);
    // HACK: wait the time for the remote to receive the message and ack it.
    // Else, message will be sent as fast as possible and it clutter the pcap.
    //usleep(4000);

    return 0;
}

static void phy_rf_mlme_orserver_tx(const mlme_set_t *set_req)
{
    return;
}

/**
 * \brief This is the default PHY interface address write API for all interface types.
 *
 * \param address_type Defines the PHY address type: PHY_MAC_64BIT, PHY_MAC_48BIT,
 *                     PHY_MAC_PANID or PHY_MAC_16BIT.
 *
 * \param address_ptr A pointer to an address.
 *
 * \return 0 Write is OK.
 * \return -1 PHY is busy.
 */
static int8_t phy_rf_address_write(phy_address_type_e address_type, uint8_t *address_ptr)
{
    if (address_ptr) {
        switch (address_type) {
            case PHY_MAC_64BIT: {
                memcpy(rf_mac_address, address_ptr, 8);
                break;
            }
            default:
                break;
        }
    }
    return 0;
}

/**
 * \brief This is the default PHY interface address write API for all interface types.
 *
 * \param extension_type Supported extension types: PHY_EXTENSION_CTRL_PENDING_BIT,
 *                       PHY_EXTENSION_SET_CHANNEL, PHY_EXTENSION_READ_CHANNEL_ENERGY
 *                       or PHY_EXTENSION_READ_LINK_STATUS.
 *
 * \param data_ptr A pointer to an 8-bit data storage for read or write purpose,
 *                 based on the extension command types.
 *
 * \return 0 State update is OK.
 * \return -1 An unsupported state or a general failure.
 */
static int8_t phy_rf_extension(phy_extension_type_e extension_type, uint8_t *data_ptr)
{
    if (data_ptr) {
        switch (extension_type) {
            /*Control MAC pending bit for Indirect data transmission*/
            case PHY_EXTENSION_CTRL_PENDING_BIT: {
                data_request_pending_flag = *data_ptr;
                break;
            }
            /*Return frame pending status*/
            case PHY_EXTENSION_READ_LAST_ACK_PENDING_STATUS: {
                *data_ptr = data_request_pending_flag;
                break;
            }
            case PHY_EXTENSION_DYNAMIC_RF_SUPPORTED: {
                *data_ptr = true;
                break;
            }
            case PHY_EXTENSION_GET_SYMBOLS_PER_SECOND: {
                *(uint32_t *)data_ptr = 100000;
                break;
            }
            case PHY_EXTENSION_SET_CCA_THRESHOLD: {
                break;
            }
            case PHY_EXTENSION_SET_CHANNEL_CCA_THRESHOLD: {
                break;
            }
            case PHY_EXTENSION_SET_TX_POWER: {
                INFO("change tx power to %u", *data_ptr);
                break;
            }
            case PHY_EXTENSION_SET_RF_CONFIGURATION: {
                break;
            }
            case PHY_EXTENSION_SET_CSMA_PARAMETERS: {
                break;
            }
            case PHY_EXTENSION_SET_802_15_4_MODE: {
                break;
            }
            case PHY_EXTENSION_FILTERING_SUPPORT: {
                break;
            }
            case PHY_EXTENSION_SET_CHANNEL: {
                TRACE(TR_CHAN, "channel switch: %2d -> %2u", channel, *data_ptr);
                channel = *data_ptr;
                break;
            }
            case PHY_EXTENSION_READ_RX_TIME: {
                struct timespec tp;
                uint32_t tmp;

                // FIXME: to make the things reproducible hack this function
                clock_gettime(CLOCK_MONOTONIC, &tp);
                tmp = tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
                data_ptr[3] = (tmp >> 0) & 0xFF;
                data_ptr[2] = (tmp >> 8) & 0xFF;
                data_ptr[1] = (tmp >> 16) & 0xFF;
                data_ptr[0] = (tmp >> 24) & 0xFF;
                break;
            }
            case PHY_EXTENSION_GET_TIMESTAMP: {
                struct timespec tp;

                // FIXME: to make the things reproducible hack this function
                clock_gettime(CLOCK_MONOTONIC, &tp);
                *(uint32_t *)data_ptr = tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
                break;
            }
            default:
                WARN("RF extention not implemented: %02x", extension_type);
                break;
        }
    }

    return 0;
}

// XXX: the phy_channel_pages needs to match the config at cmd_network.c, or the RF init fails
int8_t virtual_rf_device_register(phy_link_type_e link_type, uint16_t mtu_size)
{
    if (rf_driver_id < 0) {
        memset(&device_driver, 0, sizeof(phy_device_driver_s));
        /*Set pointer to MAC address*/
        device_driver.PHY_MAC = rf_mac_address;
        device_driver.driver_description = "VSND";

        device_driver.link_type = link_type;

        if (link_type == PHY_LINK_15_4_SUBGHZ_TYPE) {
            /*Type of RF PHY is SubGHz*/
            phy_channel_pages[0].rf_channel_configuration = &phy_subghz;
            device_driver.phy_channel_pages = phy_channel_pages;
        } else  if (link_type == PHY_LINK_15_4_2_4GHZ_TYPE) {
            /*Type of RF PHY is 2.4GHz*/
            phy_channel_pages[0].rf_channel_configuration = &phy_2_4ghz;
            device_driver.phy_channel_pages = phy_channel_pages;
        } else {
            device_driver.phy_channel_pages = NULL;
        }

        device_driver.phy_MTU = mtu_size;
        /* Add 0 extra bytes header in PHY */
        device_driver.phy_header_length = 0;
        /* Register handler functions */
        device_driver.state_control = &phy_rf_state_control;
        device_driver.tx = &phy_rf_tx;
        device_driver.address_write = phy_rf_address_write;
        device_driver.extension = &phy_rf_extension;

        rf_driver_id = arm_net_phy_register(&device_driver);

        arm_net_observer_cb_set(rf_driver_id, phy_rf_mlme_orserver_tx);
    }

    return rf_driver_id;
}
