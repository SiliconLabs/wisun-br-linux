/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef RCP_API_H
#define RCP_API_H
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "6lowpan/mac/mac_common_defines.h"

#define HIF_FHSS_TYPE_FFN_UC 0x00
#define HIF_FHSS_TYPE_FFN_BC 0x01
#define HIF_FHSS_TYPE_LFN_UC 0x02
#define HIF_FHSS_TYPE_LFN_BC 0x03
#define HIF_FHSS_TYPE_ASYNC  0x04
#define HIF_FHSS_TYPE_LFN_PA 0x06

struct fhss_ws_neighbor_timing_info;
struct fhss_ws_configuration;
struct ws_neighbor_class_entry;
struct iobuf_write;
struct iobuf_read;
struct wsbr_ctxt;
struct os_ctxt;
struct net_if;

#define RCP_HAS_RESET          0x0001
#define RCP_HAS_HWADDR         0x0002
#define RCP_HAS_RF_CONFIG_LIST 0x0004
#define RCP_HAS_RF_CONFIG      0x0008

typedef enum {
    IEEE_802_15_4_2011 = 0,    /**<IEEE 802.15.4-2011*/
    IEEE_802_15_4G_2012 = 1,   /**<IEEE 802.15.4g-2012*/
} phy_802_15_4_mode_e;

typedef enum {
    WS_TX_SLOT, // Allow transmitting only on TX slots.
    WS_TX_AND_RX_SLOT, // Allow transmitting only on TX and RX slots.
} fhss_ws_tx_allow_level_e;

enum channel_page {
    CHANNEL_PAGE_0 = 0,     ///< Page 0
    CHANNEL_PAGE_1 = 1,     ///< Page 1
    CHANNEL_PAGE_2 = 2,     ///< Page 2
    CHANNEL_PAGE_3 = 3,     ///< Page 3
    CHANNEL_PAGE_4 = 4,     ///< Page 4
    CHANNEL_PAGE_5 = 5,     ///< Page 5
    CHANNEL_PAGE_6 = 6,     ///< Page 6
    CHANNEL_PAGE_9 = 9,     ///< Page 9
    CHANNEL_PAGE_10 = 10,   ///< Page 10
    CHANNEL_PAGE_UNDEFINED  ///< Undefined
};

struct channel_list {
    enum channel_page channel_page;    /**< Channel page */
    uint8_t channel_mask[32];       /**< Channel mask. Each bit defining one channel */
    uint16_t next_channel_number;   /**< Next channel to use in the list */
};

typedef struct phy_rf_channel_configuration {
    uint32_t channel_0_center_frequency;
    uint32_t channel_spacing;
    uint32_t datarate;
    uint16_t number_of_channels;
    uint8_t  modulation;
    uint8_t  modulation_index;
    bool     fec;
    uint8_t  ofdm_option;
    uint8_t  ofdm_mcs;
    int      rcp_config_index;
    bool     use_phy_op_modes;
} phy_rf_channel_configuration_t;

typedef enum mac_data_priority {
    MAC_DATA_NORMAL_PRIORITY = 0,   /**< Normal MCPS DATA REQ */
    MAC_DATA_MEDIUM_PRIORITY = 1,   /**< Indirect Data which is polled */
    MAC_DATA_HIGH_PRIORITY = 2,     /**< MAC command usually use this and beacon */
    MAC_DATA_EXPEDITE_FORWARD = 3   /**< Expedite forward level give highest priority */
} mac_data_priority_e;

// Used by rcp_tx_req_legacy()
// See IEEE standard 802.15.4-2006 (table 41) for more details
typedef struct mcps_data_req {
    unsigned SrcAddrMode: 2;        /**< Source address mode */
    unsigned DstAddrMode: 2;        /**< Destination address mode */
    uint16_t DstPANId;              /**< Destination PAN ID */
    uint8_t DstAddr[8];             /**< Destination address */
    uint16_t msduLength;            /**< Service data unit length */
    uint8_t *msdu;                  /**< Service data unit */
    uint8_t msduHandle;             /**< Handle associated with MSDU */
    bool TxAckReq: 1;               /**< Specifies whether ACK is needed or not */
    bool PendingBit: 1;             /**< Specifies whether more fragments are to be sent or not */
    bool SeqNumSuppressed: 1;       /**< True suppress sequence number from frame. This will be only checked when 2015 extension is enabled */
    bool PanIdSuppressed: 1;        /**< True suppress PAN-id is done when possible from frame. This will be only checked when 2015 extension is enabled */
    bool ExtendedFrameExchange: 1;  /**< True for Extended Frame change. This will be only checked when 2015 extension and enhanced frame is enabled */
    mlme_security_t Key;            /**< Security key */
    uint8_t priority;               /**< See mac_data_priority_e */
    uint8_t phy_id;
    uint8_t fhss_type;              /**< FHSS policy to send that frame */
} mcps_data_req_t;

// Used by rcp_tx_req_legacy()
// Structure for IEEE 802.15.4-2015 MCPS data extension to Request
typedef struct mcps_data_req_ie_list {
    struct iovec *headerIeVectorList;    /**< Header IE element list */
    struct iovec *payloadIeVectorList;   /**< Payload IE element list */
    uint16_t headerIovLength;            /**< Header IE element list size, set 0 when no elements */
    uint16_t payloadIovLength;           /**< Payload IE element list size, set 0 when no elements */
} mcps_data_req_ie_list_t;

// See IEEE standard 802.15.4-2006 for more details
enum mcps_data_cnf_status {
    MLME_SUCCESS                    = 0x00, /**< The requested operation was completed successfully*/
    MLME_BUSY_CHAN                  = 0xe1, /**< CSMA-CA fail*/
    MLME_BUSY_RX                    = 0x01, /**< The radio is asked to change its state while receiving */
    MLME_BUSY_TX                    = 0x02, /**< The radio is asked to change its state while transmitting. */
    MLME_FORCE_TRX_OFF              = 0x03, /**< The radio is to be switched off immediately */
    MLME_IDLE                       = 0x04, /**< The CCA attempt has detected an idle channel */
    MLME_RX_ON                      = 0x06, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_TRX_OFF                    = 0x08, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_TX_ON                      = 0x09, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_COUNTER_ERROR              = 0xdb, /**< Originated messages security counter is not valid */
    MLME_IMPROPER_KEY_TYPE          = 0xdc, /**< Received Messages key used is agains't key usage policy */
    MLME_IMPROPER_SECURITY_LEVEL    = 0xdd, /**< Received Messages security level does not meet minimum security level */
    MLME_UNSUPPORTED_LEGACY         = 0xde, /**< The received frame was purportedly secured using security based on IEEE Std 802.15.4-2003, and such security is not supported by this standard. */
    MLME_UNSUPPORTED_SECURITY       = 0xdf, /**< The received frame security is not supported */
    MLME_SECURITY_FAIL              = 0xe4, /**< Cryptographic processing of the received secured frame failed. */
    MLME_FRAME_TOO_LONG             = 0xe5, /**< Either a frame resulting from processing has a length that is greater than aMaxPHYPacketSize */
    MLME_INVALID_HANDLE             = 0xe7, /**< Status for Purge request when Mac not detect proper queued message*/
    MLME_INVALID_PARAMETER          = 0xe8, /**< A parameter in the primitive is either not supported or is out of the valid range */
    MLME_TX_NO_ACK                  = 0xe9, /**< No ack was received after macMaxFrameRetries */
    MLME_NO_BEACON                  = 0xea, /**< A scan operation failed to find any network beacons */
    MLME_NO_DATA                    = 0xeb, /**< No response data were available following a request */
    MLME_NO_SHORT_ADDRESS           = 0xec, /**< Operation fail because 16-bit address is not allocated */
    MLME_PAN_ID_CONFLICT            = 0xee, /**< A PAN identifier conflict has been detected and communicated to the PAN coordinator. */
    MLME_TRANSACTION_EXPIRED        = 0xf0, /**< The transaction has expired and its information was discarded */
    MLME_TRANSACTION_OVERFLOW       = 0xf1, /**< MAC have no capacity to store the transaction */
    MLME_UNAVAILABLE_KEY            = 0xf3, /**< Received message use unknown key, or the originating device is unknown or is blacklisted with that particular key */
    MLME_UNSUPPORTED_ATTRIBUTE      = 0xf4, /**< A SET/GET request was issued with the unsupported identifier */
    MLME_INVALID_ADDRESS            = 0xf5, /**< A request to send data was unsuccessful because neither the source address parameters nor the destination address parameters were present.*/
    MLME_INVALID_INDEX              = 0xf9, /**< An attempt to write to a MAC PIB attribute that is in a table failed because the specified table index was out of range. */
    MLME_LIMIT_REACHED              = 0xfa, /**< A scan operation terminated prematurely because the number of PAN descriptors stored reached an implementation- specified maximum */
    MLME_READ_ONLY                  = 0xfb, /**< A SET request was issued with the identifier of an attribute that is read only.*/
    MLME_SCAN_IN_PROGRESS           = 0xfc, /**< Request scan request fail when scan is already active */
    // NOT-standard
    MLME_DATA_POLL_NOTIFICATION     = 0xff, /**< Thread requirement feature COMM status status for indicate for successfully data poll event to refresh neighbour data */
};

// Used by on_tx_cnf()
// See IEEE standard 802.15.4-2006 (table 42) for more details
typedef struct mcps_data_conf {
    uint8_t msduHandle;     /**< Handle associated with MSDU */
    uint8_t status;         /**< Status of the last MSDU transmission, see enum mcps_data_cnf_status */
    uint32_t timestamp;     /**< Time, in symbols, at which the data were transmitted */
    //Non-standard extension
    uint8_t cca_retries;    /**< Number of CCA retries used during sending */
    uint8_t tx_retries;     /**< Number of retries done during sending, 0 means no retries */
    struct {
        uint8_t phy_mode_id;
        uint8_t retries;
    } retry_per_rate[4];         /**< Number of retries sorted by rate */
    uint8_t success_phy_mode_id; /**< PhyModeId used to transmit the frame correctly. Only valide if status is MAC_TX_DONE */
} mcps_data_conf_t;

// Used by on_tx_cnf()
typedef struct mcps_data_conf_payload {
    const uint8_t *headerIeList;        /**< Header information IE's list without terminator*/
    const uint8_t *payloadIeList;       /**< Payload information IE's list without terminator*/
    const uint8_t *payloadPtr;          /**< Ack payload pointer */
    uint16_t headerIeListLength;        /**< Header information IE's list length in bytes */
    uint16_t payloadIeListLength;       /**< Payload information IE's list length in bytes */
    uint16_t payloadLength;             /**< Payload length in bytes */
} mcps_data_conf_payload_t;

// Used by on_rx_ind()
// See IEEE standard 802.15.4-2006 (table 43) for more details
typedef struct mcps_data_ind {
    unsigned SrcAddrMode: 2;    /**< 0x00 = no address 0x01 = reserved 0x02 = 16-bit short address 0x03 = 64-bit extended address */
    uint16_t SrcPANId;          /**< Source PAN ID */
    uint8_t SrcAddr[8];         /**< Source address */
    unsigned DstAddrMode: 2;    /**< Destination address mode */
    bool DSN_suppressed: 1;     /**< Indicate when DSN not include valid sequency id */
    bool TxAckReq: 1;           /**< Is ACK needed */
    bool PendingBit: 1;         /**< Are there more fragments to be sent */
    bool PanIdSuppressed: 1;    /**< Suppress PAN-ID if possible. 2015 extension only */
    uint16_t DstPANId;          /**< Destination PAN ID */
    uint8_t DstAddr[8];         /**< Destination address */
    uint8_t mpduLinkQuality;    /**< LQI value measured during reception of the MPDU */
    int8_t signal_dbm;          /**< This extension for normal IEEE 802.15.4 Data indication */
    uint32_t timestamp;         /**< The time, in symbols, at which the data were received */
    uint8_t DSN;                /**< Data sequence number */
    mlme_security_t Key;        /**< Security key */
    uint16_t msduLength;        /**< Data unit length */
    const uint8_t *msdu_ptr;    /**< Data unit */
} mcps_data_ind_t;

// Used by on_rx_ind()
// Structure for IEEE 802.15.4-2015 MCPS data extension to Indication
typedef struct mcps_data_ie_list {
    const uint8_t *headerIeList;        /**< Header information IE's list without terminator*/
    const uint8_t *payloadIeList;       /**< Payload information IE's list without terminator*/
    uint16_t headerIeListLength;        /**< Header information IE's list length in bytes */
    uint16_t payloadIeListLength;       /**< Payload information IE's list length in bytes */
} mcps_data_ie_list_t;

struct rcp_rail_config {
    int      index;
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint16_t chan_count;
    uint8_t  rail_phy_mode_id;
    int      phy_mode_group;
};

struct rcp {
    int  (*device_tx)(struct os_ctxt *ctxt, const void *buf, unsigned int len);
    int  (*device_rx)(struct os_ctxt *ctxt, void *buf, unsigned int len);

    void (*on_reset)(struct wsbr_ctxt *ctxt);
    void (*on_tx_cnf)(int8_t net_if_id, const struct mcps_data_conf *conf, const struct mcps_data_conf_payload *payload);
    void (*on_rx_ind)(int8_t net_if_id, const struct mcps_data_ind *conf, const struct mcps_data_ie_list *payload);
    void (*on_rx_err)(uint8_t src[8], uint8_t status);
    void (*on_crc_error)(struct os_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter);

    uint32_t init_state;
    uint32_t version_api;
    uint32_t version_fw;
    const char *version_label;
    uint32_t neighbors_table_size;
    uint8_t lfn_limit;
    uint8_t  eui64[8];
    uint32_t frame_counter;
    struct rcp_rail_config *rail_config_list;
};

void rcp_noop(void);
void rcp_reset(void);
void rcp_reset_stack(void);
void rcp_start(uint16_t channel, uint16_t panid, bool coordinator);
void rcp_allocate_fhss(const struct fhss_ws_configuration *timing_info);
void rcp_register_fhss(void);
void rcp_unregister_fhss(void);
void rcp_release_fhss(void);
void rcp_get_hw_addr(void);
void rcp_get_rx_sensitivity(void);
void rcp_get_rf_config_list(void);
void rcp_set_rf_config_legacy(const struct phy_rf_channel_configuration *config);
void rcp_set_rf_config(const struct phy_rf_channel_configuration *config);
void rcp_set_regional_regulation(uint32_t val);
void rcp_set_rx_on_idle(bool enable);
void rcp_set_802154_mode(phy_802_15_4_mode_e val);
void rcp_set_ack_wait_duration(uint16_t val);
void rcp_set_cca_threshold(uint8_t number_of_channels, uint8_t default_dbm,
                           uint8_t high_limit, uint8_t low_limit);
void rcp_set_max_rf_retry(uint8_t max_cca_failure, uint8_t max_tx_failure,
                          uint16_t blacklist_min_ms, uint16_t blacklist_max_ms);
void rcp_set_max_mac_retry(uint8_t val);
void rcp_set_max_csma_backoffs(uint8_t val);
void rcp_set_min_be(uint8_t val);
void rcp_set_max_be(uint8_t val);
void rcp_set_max_async_duration(uint32_t val);
void rcp_set_tx_power(int8_t val);
void rcp_set_fhss_timings(const struct fhss_ws_configuration *timing_info);
void rcp_set_fhss_parent(const uint8_t parent[8],
                         const struct fhss_ws_neighbor_timing_info *timing_info,
                         bool force_synch);
void rcp_set_fhss_neighbor(const uint8_t neigh[8],
                           const struct fhss_ws_neighbor_timing_info *timing_info);
void rcp_drop_fhss_neighbor(const uint8_t eui64[8]);
void rcp_set_fhss_hop_count(int hop_count);
void rcp_set_coordinator_mac64(uint8_t val[8]);
void rcp_set_coordinator_mac16(uint16_t val);
void rcp_set_tx_allowance_level(fhss_ws_tx_allow_level_e normal,
                                fhss_ws_tx_allow_level_e expedited_forwarding);
void rcp_set_security(bool enable);
void rcp_set_accept_unknown_secured_frames(bool enable);
void rcp_set_frame_counter_per_key(bool enable);
void rcp_set_frame_counter(int slot, uint32_t val);
void rcp_get_frame_counter(int slot);
void rcp_set_key(uint8_t slot, const uint8_t *lookup_data, const uint8_t *key);
void rcp_set_default_key_source(const uint8_t lookup_data[8]);
void rcp_set_neighbor(uint8_t slot, uint16_t panid, uint16_t mac16,
                      uint8_t *mac64, uint32_t frame_counter);
void rcp_enable_mac_filter(bool forward_unknown);
void rcp_disable_mac_filter(void);
void rcp_add_mac_filter_entry(uint8_t mac64[8], bool forward);
void rcp_clear_mac_filters(void);

void rcp_abort_edfe(void);
void rcp_tx_req_legacy(const struct mcps_data_req *tx_req,
                       const struct iovec *header_ie,
                       const struct iovec *payload_ie,
                       const struct iovec *mpx_ie,
                       const struct channel_list *channel_list);
void rcp_tx_req(const uint8_t *frame, int frame_len,
                const struct ws_neighbor_class_entry *neighbor_ws,
                uint8_t handle, uint8_t fhss_type, bool is_edfe, uint8_t priority, uint8_t phy_id);
void rcp_tx_drop(uint8_t handle);

// Low-layer function to access the RCP
void rcp_rx(struct wsbr_ctxt *ctxt);
void rcp_tx(struct wsbr_ctxt *ctxt, struct iobuf_write *buf);

// Only used by the fuzzer
struct rcp_rx_cmds {
    uint32_t cmd;
    uint32_t prop;
    void (*fn)(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf);
};
extern struct rcp_rx_cmds rx_cmds[];
uint8_t rcp_get_spinel_hdr(void);

#endif
