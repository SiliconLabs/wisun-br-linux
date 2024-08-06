/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2016, The OpenThread Authors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SPINEL_DEFS_H
#define SPINEL_DEFS_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct iobuf_read;
struct iobuf_write;

enum {
    SPINEL_STATUS_OK                  = 0,
    SPINEL_STATUS_FAILURE             = 1,

    SPINEL_STATUS_RESET__BEGIN        = 0x70,
    SPINEL_STATUS_RESET__END          = 0x80,

    SPINEL_STATUS_VENDOR__BEGIN       = 0x3C00,
    SPINEL_STATUS_VENDOR__END         = 0x4000,

    SPINEL_STATUS_EXPERIMENTAL__BEGIN = 0x1F0000,
    SPINEL_STATUS_EXPERIMENTAL__END   = 0x200000,
};

enum {
    SPINEL_CMD_NOOP                = 0,
    SPINEL_CMD_RESET               = 1,
    SPINEL_CMD_PROP_GET            = 2,
    SPINEL_CMD_PROP_SET            = 3,
    SPINEL_CMD_PROP_INSERT         = 4, /* Unused */
    SPINEL_CMD_PROP_REMOVE         = 5, /* Unused */
    SPINEL_CMD_PROP_IS             = 6,
    SPINEL_CMD_PROP_INSERTED       = 7, /* Unused */
    SPINEL_CMD_PROP_REMOVED        = 8, /* Unused */

    SPINEL_CMD_RCP_PING            = 24,
    SPINEL_CMD_BOOTLOADER_UPDATE   = 25,

    SPINEL_CMD_VENDOR__BEGIN       = 0x3C00,
    SPINEL_CMD_VENDOR__END         = 0x4000,

    SPINEL_CMD_EXPERIMENTAL__BEGIN = 0x1F0000,
    SPINEL_CMD_REPLAY_TIMERS       = SPINEL_CMD_EXPERIMENTAL__BEGIN,     /* Debug only */
    SPINEL_CMD_REPLAY_INTERFACE    = SPINEL_CMD_EXPERIMENTAL__BEGIN + 1, /* Debug only */
    SPINEL_CMD_EXPERIMENTAL__END   = 0x200000,
};

/**
 * Property Keys
 *
 * The properties are broken up into several sections, each with a
 * reserved ranges of property identifiers:
 *
 *    Name         | Range (Inclusive)              | Description
 *    -------------|--------------------------------|------------------------
 *    Core         | 0x000 - 0x01F, 0x1000 - 0x11FF | Spinel core
 *    PHY          | 0x020 - 0x02F, 0x1200 - 0x12FF | Radio PHY layer
 *    MAC          | 0x030 - 0x03F, 0x1300 - 0x13FF | MAC layer
 *    NET          | 0x040 - 0x04F, 0x1400 - 0x14FF | Network
 *    Thread       | 0x050 - 0x05F, 0x1500 - 0x15FF | Thread
 *    IPv6         | 0x060 - 0x06F, 0x1600 - 0x16FF | IPv6
 *    Stream       | 0x070 - 0x07F, 0x1700 - 0x17FF | Stream
 *    MeshCop      | 0x080 - 0x08F, 0x1800 - 0x18FF | Thread Mesh Commissioning
 *    OpenThread   |                0x1900 - 0x19FF | OpenThread specific
 *    Server       | 0x0A0 - 0x0AF                  | ALOC Service Server
 *    RCP          | 0x0B0 - 0x0FF                  | RCP specific
 *    Interface    | 0x100 - 0x1FF                  | Interface (e.g., UART)
 *    PIB          | 0x400 - 0x4FF                  | 802.15.4 PIB
 *    Counter      | 0x500 - 0x7FF                  | Counters (MAC, IP, etc).
 *    RCP          | 0x800 - 0x8FF                  | RCP specific property (extended)
 *    Nest         |                0x3BC0 - 0x3BFF | Nest (legacy)
 *    Vendor       |                0x3C00 - 0x3FFF | Vendor specific
 *    Debug        |                0x4000 - 0x43FF | Debug related
 *    Experimental |          2,000,000 - 2,097,151 | Experimental use only
 *
 */
enum {
    SPINEL_PROP_LAST_STATUS         = 0,
    SPINEL_PROP_HWADDR              = 8,

    SPINEL_PROP_BASE_EXT__BEGIN     = 0x1000,
    SPINEL_PROP_BASE_EXT__END       = 0x1100,

    SPINEL_PROP_PHY__BEGIN          = 0x020,
    SPINEL_PROP_PHY_ENABLED         = SPINEL_PROP_PHY__BEGIN + 0,  ///< [b]
    SPINEL_PROP_PHY_CHAN            = SPINEL_PROP_PHY__BEGIN + 1,  ///< [C]
    SPINEL_PROP_PHY_CHAN_SUPPORTED  = SPINEL_PROP_PHY__BEGIN + 2,  ///< [A(C)]
    SPINEL_PROP_PHY_FREQ            = SPINEL_PROP_PHY__BEGIN + 3,  ///< kHz [L]
    SPINEL_PROP_PHY_CCA_THRESHOLD   = SPINEL_PROP_PHY__BEGIN + 4,  ///< dBm [c]
    SPINEL_PROP_PHY_TX_POWER        = SPINEL_PROP_PHY__BEGIN + 5,  ///< [c]
    SPINEL_PROP_PHY_RSSI            = SPINEL_PROP_PHY__BEGIN + 6,  ///< dBm [c]
    SPINEL_PROP_PHY_RX_SENSITIVITY  = SPINEL_PROP_PHY__BEGIN + 7,  ///< dBm [c]
    SPINEL_PROP_PHY_PCAP_ENABLED    = SPINEL_PROP_PHY__BEGIN + 8,  ///< [b]
    SPINEL_PROP_PHY_CHAN_PREFERRED  = SPINEL_PROP_PHY__BEGIN + 9,  ///< [A(C)]
    SPINEL_PROP_PHY_FEM_LNA_GAIN    = SPINEL_PROP_PHY__BEGIN + 10, ///< dBm [c]
    SPINEL_PROP_PHY_CHAN_MAX_POWER  = SPINEL_PROP_PHY__BEGIN + 11,
    SPINEL_PROP_PHY_REGION_CODE     = SPINEL_PROP_PHY__BEGIN + 12,
    SPINEL_PROP_PHY__END            = 0x030,

    SPINEL_PROP_PHY_EXT__BEGIN      = 0x1200,
    SPINEL_PROP_PHY_EXT__END        = 0x1300,

    SPINEL_PROP_MAC__BEGIN          = 0x030,
    SPINEL_PROP_MAC_15_4_LADDR      = SPINEL_PROP_MAC__BEGIN + 4,
    SPINEL_PROP_MAC_15_4_SADDR      = SPINEL_PROP_MAC__BEGIN + 5,
    SPINEL_PROP_MAC_15_4_PANID      = SPINEL_PROP_MAC__BEGIN + 6,
    SPINEL_PROP_MAC__END            = 0x040,

    SPINEL_PROP_MAC_EXT__BEGIN      = 0x1300,
    SPINEL_PROP_MAC_EXT__END        = 0x1400,

    SPINEL_PROP_NET__BEGIN          = 0x040,
    SPINEL_PROP_NET__END            = 0x050,

    SPINEL_PROP_NET_EXT__BEGIN      = 0x1400,
    SPINEL_PROP_NET_EXT__END        = 0x1500,

    SPINEL_PROP_THREAD__BEGIN       = 0x050,
    SPINEL_PROP_THREAD__END         = 0x060,

    SPINEL_PROP_THREAD_EXT__BEGIN   = 0x1500,
    SPINEL_PROP_THREAD_EXT__END     = 0x1600,

    SPINEL_PROP_IPV6__BEGIN         = 0x060,
    SPINEL_PROP_IPV6__END           = 0x070,

    SPINEL_PROP_IPV6_EXT__BEGIN     = 0x1600,
    SPINEL_PROP_IPV6_EXT__END       = 0x1700,

    SPINEL_PROP_STREAM__BEGIN       = 0x070,
    SPINEL_PROP_STREAM_RAW          = SPINEL_PROP_STREAM__BEGIN + 1,
    SPINEL_PROP_STREAM__END         = 0x080,

    SPINEL_PROP_STREAM_EXT__BEGIN   = 0x1700,
    SPINEL_PROP_STREAM_EXT__END     = 0x1800,

    SPINEL_PROP_MESHCOP__BEGIN      = 0x080,
    SPINEL_PROP_MESHCOP__END        = 0x090,

    SPINEL_PROP_MESHCOP_EXT__BEGIN  = 0x1800,
    SPINEL_PROP_MESHCOP_EXT__END    = 0x1900,

    SPINEL_PROP_OPENTHREAD__BEGIN   = 0x1900,
    SPINEL_PROP_OPENTHREAD__END     = 0x2000,

    SPINEL_PROP_SERVER__BEGIN       = 0x0A0,
    SPINEL_PROP_SERVER__END         = 0x0B0,

    SPINEL_PROP_RCP__BEGIN          = 0x0B0,
    SPINEL_PROP_RCP__END            = 0x100,

    SPINEL_PROP_INTERFACE__BEGIN    = 0x100,
    SPINEL_PROP_INTERFACE__END      = 0x200,

    SPINEL_PROP_15_4_PIB__BEGIN     = 0x400,
    SPINEL_PROP_15_4_PIB__END       = 0x500,

    SPINEL_PROP_CNTR__BEGIN         = 0x500,
    SPINEL_PROP_CNTR__END           = 0x800,

    SPINEL_PROP_RCP_EXT__BEGIN      = 0x800,
    SPINEL_PROP_RCP_EXT__END        = 0x900,

    SPINEL_PROP_NEST__BEGIN         = 0x3BC0,
    SPINEL_PROP_NEST__END           = 0x3C00,

    SPINEL_PROP_VENDOR__BEGIN       = 0x3C00,
    SPINEL_PROP_VENDOR__END         = 0x4000,

    SPINEL_PROP_DEBUG__BEGIN        = 0x4000,
    SPINEL_PROP_DEBUG__END          = 0x4400,

    SPINEL_PROP_EXPERIMENTAL__BEGIN = 2000000,
    SPINEL_PROP_WS__BEGIN           = SPINEL_PROP_EXPERIMENTAL__BEGIN + 0,
    SPINEL_PROP_WS_15_4_MODE                        = SPINEL_PROP_WS__BEGIN +  0,
    SPINEL_PROP_WS_RF_CONFIGURATION_LEGACY          = SPINEL_PROP_WS__BEGIN +  1,
    SPINEL_PROP_WS_START                            = SPINEL_PROP_WS__BEGIN +  2,
    SPINEL_PROP_WS_RESET                            = SPINEL_PROP_WS__BEGIN +  3,
    SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS            = SPINEL_PROP_WS__BEGIN +  4,
    SPINEL_PROP_WS_CCA_THRESHOLD_START              = SPINEL_PROP_WS__BEGIN +  5,
    SPINEL_PROP_WS_CCA_THRESHOLD                    = SPINEL_PROP_WS__BEGIN +  6,
    SPINEL_PROP_WS_MAX_FRAME_RETRIES                = SPINEL_PROP_WS__BEGIN +  7,
    SPINEL_PROP_WS_ACK_WAIT_DURATION                = SPINEL_PROP_WS__BEGIN +  8,
    SPINEL_PROP_WS_RX_ON_WHEN_IDLE                  = SPINEL_PROP_WS__BEGIN +  9,
    SPINEL_PROP_WS_TX_POWER                         = SPINEL_PROP_WS__BEGIN + 10,
    SPINEL_PROP_WS_EDFE_FORCE_STOP                  = SPINEL_PROP_WS__BEGIN + 11,

    SPINEL_PROP_WS_BEACON_PAYLOAD                   = SPINEL_PROP_WS__BEGIN + 12,
    SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH            = SPINEL_PROP_WS__BEGIN + 13,
    SPINEL_PROP_WS_ASSOCIATION_PERMIT               = SPINEL_PROP_WS__BEGIN + 14,
    SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE = SPINEL_PROP_WS__BEGIN + 15,
    SPINEL_PROP_WS_COORD_SHORT_ADDRESS              = SPINEL_PROP_WS__BEGIN + 16,
    SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS           = SPINEL_PROP_WS__BEGIN + 17,

    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL      = SPINEL_PROP_WS__BEGIN + 18,
    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE         = SPINEL_PROP_WS__BEGIN + 19,
    SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE          = SPINEL_PROP_WS__BEGIN + 20,
    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX           = SPINEL_PROP_WS__BEGIN + 21,
    SPINEL_PROP_WS_DEFAULT_KEY_SOURCE               = SPINEL_PROP_WS__BEGIN + 22,
    SPINEL_PROP_WS_SECURITY_ENABLED                 = SPINEL_PROP_WS__BEGIN + 23,
    SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE      = SPINEL_PROP_WS__BEGIN + 24,
    SPINEL_PROP_WS_KEY_TABLE                        = SPINEL_PROP_WS__BEGIN + 25,
    SPINEL_PROP_WS_FRAME_COUNTER                    = SPINEL_PROP_WS__BEGIN + 26,
    SPINEL_PROP_WS_DEVICE_TABLE                     = SPINEL_PROP_WS__BEGIN + 27,
    SPINEL_PROP_STREAM_STATUS                       = SPINEL_PROP_WS__BEGIN + 28,
    SPINEL_PROP_WS_MLME_IND                         = SPINEL_PROP_WS__BEGIN + 29,
    SPINEL_PROP_WS_MAX_CSMA_BACKOFFS                = SPINEL_PROP_WS__BEGIN + 40,
    SPINEL_PROP_WS_MIN_BE                           = SPINEL_PROP_WS__BEGIN + 41,
    SPINEL_PROP_WS_MAX_BE                           = SPINEL_PROP_WS__BEGIN + 42,
    SPINEL_PROP_WS_REQUEST_RESTART                  = SPINEL_PROP_WS__BEGIN + 43,
    SPINEL_PROP_WS_MAC_FILTER_START                 = SPINEL_PROP_WS__BEGIN + 45,
    SPINEL_PROP_WS_MAC_FILTER_CLEAR                 = SPINEL_PROP_WS__BEGIN + 46,
    SPINEL_PROP_WS_MAC_FILTER_ADD_LONG              = SPINEL_PROP_WS__BEGIN + 47,
    SPINEL_PROP_WS_MAC_FILTER_STOP                  = SPINEL_PROP_WS__BEGIN + 48,
    SPINEL_PROP_WS_MCPS_DROP                        = SPINEL_PROP_WS__BEGIN + 49,
    SPINEL_PROP_WS_DEVICE_STATISTICS                = SPINEL_PROP_WS__BEGIN + 50,
    SPINEL_PROP_WS_DEVICE_STATISTICS_CLEAR          = SPINEL_PROP_WS__BEGIN + 51,
    SPINEL_PROP_WS_REGIONAL_REGULATION              = SPINEL_PROP_WS__BEGIN + 52,
    SPINEL_PROP_WS_RX_SENSITIVITY                   = SPINEL_PROP_WS__BEGIN + 53,
    SPINEL_PROP_WS_GLOBAL_TX_DURATION               = SPINEL_PROP_WS__BEGIN + 54,
    SPINEL_PROP_WS_RF_CONFIGURATION_LIST            = SPINEL_PROP_WS__BEGIN + 58,
    SPINEL_PROP_WS_RCP_CRC_ERR                      = SPINEL_PROP_WS__BEGIN + 59,
    SPINEL_PROP_WS_ASYNC_FRAGMENTATION              = SPINEL_PROP_WS__BEGIN + 60,
    SPINEL_PROP_FRAME                               = SPINEL_PROP_WS__BEGIN + 61,
    SPINEL_PROP_RF_CONFIG                           = SPINEL_PROP_WS__BEGIN + 62,
    SPINEL_PROP_WS_ENABLE_EDFE                      = SPINEL_PROP_WS__BEGIN + 63,

    SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY     = SPINEL_PROP_WS__BEGIN + 30,
    SPINEL_PROP_WS_FHSS_CREATE                      = SPINEL_PROP_WS__BEGIN + 31,
    SPINEL_PROP_WS_FHSS_DELETE                      = SPINEL_PROP_WS__BEGIN + 32,
    SPINEL_PROP_WS_FHSS_REGISTER                    = SPINEL_PROP_WS__BEGIN + 33,
    SPINEL_PROP_WS_FHSS_UNREGISTER                  = SPINEL_PROP_WS__BEGIN + 34,
    SPINEL_PROP_WS_FHSS_SET_CONF                    = SPINEL_PROP_WS__BEGIN + 35,
    SPINEL_PROP_WS_FHSS_SET_HOP_COUNT               = SPINEL_PROP_WS__BEGIN + 36,
    SPINEL_PROP_WS_FHSS_SET_PARENT                  = SPINEL_PROP_WS__BEGIN + 37,
    SPINEL_PROP_WS_FHSS_UPDATE_NEIGHBOR             = SPINEL_PROP_WS__BEGIN + 38,
    SPINEL_PROP_WS_FHSS_DROP_NEIGHBOR               = SPINEL_PROP_WS__BEGIN + 44,
    SPINEL_PROP_WS_FHSS_SET_TX_ALLOWANCE_LEVEL      = SPINEL_PROP_WS__BEGIN + 39,
    SPINEL_PROP_EXPERIMENTAL__END   = 0x200000,
};

const char *spinel_cmd_str(int cmd);
const char *spinel_prop_str(int prop);
bool spinel_prop_is_valid(struct iobuf_read *buf, int prop);
void spinel_trace(const uint8_t *buf, size_t buf_len, const char *prefix);

#endif
