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

/** \file mlme.h
 * \brief MLME API
 */

#ifndef MLME_H_
#define MLME_H_

#include <stdbool.h>
#include "nanostack/mac/mac_common_defines.h"
#include "nanostack/mac/channel_list.h"

/**
 * @brief struct mlme_pan_descriptor_t PAN descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 55) for more details
 */
typedef struct mlme_pan_descriptor_s {
    unsigned CoordAddrMode: 2;  /**<Coordinator address mode MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint16_t CoordPANId;        /**<PAN-id */
    uint8_t CoordAddress[8];    /**< Coordinator based CoordAddrMode */
    uint8_t LogicalChannel;     /**< Pan's Logical channel */
    uint8_t ChannelPage;        /**< Channel Page*/
    uint8_t SuperframeSpec[2];  /**< Superframe specification */
    bool GTSPermit: 1;          /**< true = GTS enabled false = disabled  */
    uint8_t LinkQuality;        /**< Link quality based on received packet to Coordinator 0-0xff  */
    uint32_t Timestamp;         /**< Time stamp for received packet  */
    uint8_t SecurityFailure;    /**< Indicates payload security failure  */
    mlme_security_t Key;        /**< PAN beacon used security AUX header  */
} mlme_pan_descriptor_t;

/**
 * @brief struct mlme_command_type_t Command type enumeration
 *
 * See IEEE standard 802.15.4-2006 (table 82) for more details
 */
typedef enum {
    ASSOCIATION_REQUEST = 1,            /**<Assocation request (Not supported)*/
    ASSOCIATION_RESPONSE = 2,           /**<Assocation response (Not supported)*/
    DISASSOCIATION_NOTIFICATION = 3,    /**<Disasocation Notification (Not supported)*/
    DATA_REQUEST = 4,                   /**<Data Request */
    PAN_ID_CONFLICT_NOTIFICATION = 5,   /**<Pan ID conflict notification (Not supported)*/
    ORPHAN_NOTIFICATION = 6,            /**<Orphan Notification (Not supported)*/
    BEACON_REQUEST = 7,                 /**<Beacon request */
    COORDINATOR_REALIGNMENT = 8,        /**<Coordinator Realignment (Not supported)*/
    GTS_REQUEST = 9                     /**<GTS request (Not supported)*/
                  //Reserved
} mlme_command_type_t;

/**
 * @brief struct mlme_key_usage_descriptor_t Key usage descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 90) for more details
 */
typedef struct mlme_key_usage_descriptor_s {
    unsigned FrameType: 3; /**<0 = Beacon Frame, 1 = Data Frame or 3 Command Frame */
    unsigned CommandFrameIdentifier: 4; /**< Set this part only when FrameType is 3 */
} mlme_key_usage_descriptor_t;

/**
 * @brief struct mlme_key_device_descriptor_t Key usage descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 91) for more details
 */
typedef struct mlme_key_device_descriptor_s {
    uint8_t DeviceDescriptorHandle; /**< User defined unique ID to key User */
    bool UniqueDevice: 1;           /**< true = Key description is for Key Pair Key usage only, False = group key  */
    bool Blacklisted: 1;            /**< true = Description is black listed, False = valid to use */
} mlme_key_device_descriptor_t;

/**
 * @brief enum mlme_security_type_t Security type enumeration
 *
 * See IEEE standard 802.15.4-2006 (table 95) for more details
 */
typedef enum {
    SEC_NONE = 0,       /**< No payload encode and authentication */
    SEC_MIC32 = 1,      /**< No payload encode with 32-bit MIC authentication */
    SEC_MIC64 = 2,      /**< No payload encode with 64-bit MIC authentication */
    SEC_MIC128 = 3,     /**< No payload encode with 128-bit MIC authentication */
    SEC_ENC = 4,        /**< Payload encode enabled and without authentication */
    SEC_ENC_MIC32 = 5,  /**< Payload encode enabled with 32-bit MIC authentication */
    SEC_ENC_MIC64 = 6,  /**< Payload encode enabled with 64-bit MIC authentication */
    SEC_ENC_MIC128 = 7  /**< Payload encode enabled with 128-bit MIC authentication */
} mlme_security_type_t;

/**
 * @brief struct mlme_security_level_descriptor_t Security level descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 92) for more details
 */
typedef struct mlme_security_level_descriptor_s {
    unsigned FrameType: 3; /**<0 = Beacon Frame, 1 = Data Frame or 3 Command Frame */
    unsigned CommandFrameIdentifier: 4; /**< Set this part only when FrameType is 3 */
    unsigned SecurityMinimum: 3; /**< Define Minimum acceptable security level for RX */
    bool DeviceOverrideSecurityMinimum: 1; /**< Set false */
} mlme_security_level_descriptor_t;

/**
 * @brief struct mlme_device_descriptor_t Device descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 93) for more details
 */
typedef struct mlme_device_descriptor_s {
    uint16_t PANId;         /**< Pan-id */
    uint16_t ShortAddress;  /**< Device 16-bit short address 0xffff means not defined */
    uint8_t ExtAddress[8];  /**< Device Extended 64-bit address */
    uint32_t FrameCounter;  /**< Security Frame counter */
    bool Exempt: 1;         /**< Set false */
} mlme_device_descriptor_t;

/**
 * @brief struct mlme_key_id_lookup_descriptor_t Key id lookup descriptor
 *
 * See IEEE standard 802.15.4-2006 (table 94) for more details
 */
typedef struct mlme_key_id_lookup_descriptor_s {
    uint8_t LookupData[9];      /**< Key Lookup data */
    unsigned LookupDataSize: 1; /**< Key Lookup data size 0= 5 1 is 9 bytes */
} mlme_key_id_lookup_descriptor_t;


/**
 * @brief struct mlme_key_descriptor_entry_t Key descriptor entry
 *
 * See IEEE standard 802.15.4-2006 (table 89) for more details
 */
typedef struct mlme_key_descriptor_entry_s {
    mlme_key_id_lookup_descriptor_t *KeyIdLookupList;   /**< List of Key lookup data for this descriptor*/
    uint8_t KeyIdLookupListEntries;                     /**< Number of entries in KeyIdLookupList*/
    mlme_key_device_descriptor_t *KeyDeviceList;        /**< List of descriptor user entries indicating which devices are valid or blacklisted */
    uint8_t KeyDeviceListEntries;                       /**< Number of entries in KeyDeviceList*/
    mlme_key_usage_descriptor_t *KeyUsageList;          /**< List of descriptor entries indicating which frame types this key may be used with*/
    uint8_t KeyUsageListEntries;                        /**< Number of entries in KeyUsageList*/
    uint8_t Key[16];                                    /**< Actual value of Security key*/
} mlme_key_descriptor_entry_t;

/**
 * @brief MLME primitive error statuses
 *
 * See IEEE standard 802.15.4-2006 for more details
 */
#define MLME_SUCCESS                    0x00 /**< The requested operation was completed successfully*/
#define MLME_BUSY_CHAN                  0xe1 /**< CSMA-CA fail*/
#define MLME_BUSY_RX                    0x01 /**< The radio is asked to change its state while receiving */
#define MLME_BUSY_TX                    0x02 /**< The radio is asked to change its state while transmitting. */
#define MLME_FORCE_TRX_OFF              0x03 /**< The radio is to be switched off immediately */
#define MLME_IDLE                       0x04 /**< The CCA attempt has detected an idle channel */
#define MLME_RX_ON                      0x06 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_TRX_OFF                    0x08 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_TX_ON                      0x09 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_COUNTER_ERROR              0xdb /**< Originated messages security counter is not valid */
#define MLME_IMPROPER_KEY_TYPE          0xdc /**< Received Messages key used is agains't key usage policy */
#define MLME_IMPROPER_SECURITY_LEVEL    0xdd /**< Received Messages security level does not meet minimum security level */
#define MLME_UNSUPPORTED_LEGACY         0xde /**< The received frame was purportedly secured using security based on IEEE Std 802.15.4-2003, and such security is not supported by this standard. */
#define MLME_UNSUPPORTED_SECURITY       0xdf /**< The received frame security is not supported */
#define MLME_SECURITY_FAIL              0xe4 /**< Cryptographic processing of the received secured frame failed. */
#define MLME_FRAME_TOO_LONG             0xe5 /**< Either a frame resulting from processing has a length that is greater than aMaxPHYPacketSize */
#define MLME_INVALID_HANDLE             0xe7 /**< Status for Purge request when Mac not detect proper queued message*/
#define MLME_INVALID_PARAMETER          0xe8 /**< A parameter in the primitive is either not supported or is out of the valid range */
#define MLME_TX_NO_ACK                  0xe9 /**< No ack was received after macMaxFrameRetries */
#define MLME_NO_BEACON                  0xea /**< A scan operation failed to find any network beacons */
#define MLME_NO_DATA                    0xeb /**< No response data were available following a request */
#define MLME_NO_SHORT_ADDRESS           0xec /**< Operation fail because 16-bit address is not allocated */
#define MLME_PAN_ID_CONFLICT            0xee /**< A PAN identifier conflict has been detected and communicated to the PAN coordinator. */
#define MLME_TRANSACTION_EXPIRED        0xf0 /**< The transaction has expired and its information was discarded */
#define MLME_TRANSACTION_OVERFLOW       0xf1 /**< MAC have no capacity to store the transaction */
#define MLME_UNAVAILABLE_KEY            0xf3 /**< Received message use unknown key, or the originating device is unknown or is blacklisted with that particular key */
#define MLME_UNSUPPORTED_ATTRIBUTE      0xf4 /**< A SET/GET request was issued with the unsupported identifier */
#define MLME_INVALID_ADDRESS            0xf5 /**< A request to send data was unsuccessful because neither the source address parameters nor the destination address parameters were present.*/
#define MLME_INVALID_INDEX              0xf9 /**< An attempt to write to a MAC PIB attribute that is in a table failed because the specified table index was out of range. */
#define MLME_LIMIT_REACHED              0xfa /**< A scan operation terminated prematurely because the number of PAN descriptors stored reached an implementation- specified maximum */
#define MLME_READ_ONLY                  0xfb /**< A SET request was issued with the identifier of an attribute that is read only.*/
#define MLME_SCAN_IN_PROGRESS           0xfc /**< Request scan request fail when scan is already active */
//NOT-standard
#define MLME_DATA_POLL_NOTIFICATION     0xff /**< Thread requirement feature COMM status status for indicate for successfully data poll event to refresh neighbour data */

/**
 * @brief enum mlme_attr_t MLME attributes used with GET and SET primitives
 *
 * See IEEE standard 802.15.4-2006 (table 86) for more details
 */
typedef enum {
    phyCurrentChannel = 0x00,       /*<Current RF channel*/
    macAckWaitDuration = 0x40,      /*<Integer, n. of symbols*/
    macAutoRequest = 0x42,          /*<Boolean, if device automatically sends data request on beacon*/
    macBeaconOrder = 0x47,          /*<Integer 0–15, Beacon tx period, 15 = no periodic beacon*/
    macBeaconTxTime = 0x48,         /*<Integer 0x000000–0xffffff, symbols, when last beacon was transmitted*/
    macBSN = 0x49,                  /*<Integer 0x00–0xff, Beacon sequence number*/
    macCoordExtendedAddress = 0x4a, /*<64-bit IEEE of coordinator*/
    macCoordShortAddress = 0x4b,    /*<16-bit addr of coordinator*/
    macDSN = 0x4c,                  /*<Integer 0x00–0xff, Data frame sequence number*/
    macMaxBE = 0x57,                /*<Integer 3–8, max value of back off exponent*/
    macMaxCSMABackoffs = 0x4e,      /*<Integer 0–5*/
    macMaxFrameTotalWaitTime = 0x58,/*<Integer, max of CAP symbols while waiting for data requested by DREQ or PEND*/
    macMaxFrameRetries = 0x59,      /*<Integer 0–7*/
    macMinBE = 0x4f,                /*<Integer 0–macMaxBE*/
    macPANId = 0x50,                /*<PAN ID, 16 bits*/
    macResponseWaitTime = 0x5a,     /*<Integer 2–64  The maximum time in SuperFrameDurations to wait for responses*/
    macRxOnWhenIdle = 0x52,         /*<Boolean*/
    macSecurityEnabled = 0x5d,      /*<Boolean*/
    macShortAddress = 0x53,         /*<Short address, 16 bits*/
    macSuperframeOrder = 0x54,      /*<Integer 0–15, The length of the active portion of the outgoing super frame, 15 = none*/
    macKeyTable = 0x71,             /*<A table of KeyDescriptor entries, each containing keys and related information required for secured communications.*/
    macKeyTableEntries = 0x72,      /*<The number of entries in macKeyTable.*/
    macDeviceTable = 0x73,          /*<List of Descriptor entries, each indicating a remote device*/
    macDeviceTableEntries = 0x74,   /*<The number of entries in macDeviceTable.*/
    macSecurityLevelTable = 0x75,   /*<A table of SecurityLevelDescriptor entries*/
    macSecurityLevelTableEntries = 0x76,    /*<The number of entries in macSecurityLevelTable*/
    macFrameCounter = 0x77,         /*<The outgoing frame counter*/
    macAutoRequestSecurityLevel = 0x78, /*<0x00–0x07  The security level used for automatic data requests.*/
    macAutoRequestKeyIdMode = 0x79,      /*< The key identifier mode used for automatic data requests.*/
    macAutoRequestKeySource = 0x7a, /*<Key source for automatic data*/
    macAutoRequestKeyIndex = 0x7b,  /*<The index of the key used for automatic data*/
    macDefaultKeySource = 0x7c,      /*<Default key source*/
    //NON standard extension
    macGlobalTxDuration = 0xe8,     /*< Global transmission duration. */
    macRegionalRegulation = 0xe9,   /*< Regional regulation. */
    macRxSensitivity = 0xea,        /*< Receiver sensitivity of the configured phy. */
    macDeviceStatisticsClear = 0xeb,/*< Clear device statistics. */
    macDeviceStatistics = 0xec,     /*< Get device statistics. */
    macFilterStop = 0xed,           /*< Stops MAC level filter. */
    macFilterAddLong = 0xee,        /*< Adds a filter using EUI-64. */
    macFilterClear = 0xef,          /*< Deletes all filters. */
    macFilterStart = 0xf0,          /*< Starts a MAC level filter. */
    macRequestRestart = 0xf1,       /*< Configure failed packet data request restart */
    macEdfeForceStop = 0xf2,        /*< Use this command for Data wait timeout at LLC: Mac stop Edfe session data wait and enable normal FHSS mode */
    macSetDataWhitening = 0xf3,     /*< Enable or disable data whitening, boolean true for enable, false for disable */
    macCCAThresholdStart = 0xf4,    /*< Start automatic CCA threshold */
    mac802_15_4Mode = 0xf6,         /*<IEEE 802.15.4 mode*/
    macTXPower = 0xf8,              /*<TX output power*/
    macCCAThreshold = 0xf9,         /*<CCA threshold*/
    macMultiCSMAParameters = 0xfa,  /*<Multi CSMA parameters*/
    macRfConfiguration = 0xfb,      /*<RF channel configuration parameters*/
    macAcceptByPassUnknowDevice = 0xfc,  /*< Accept data trough MAC if packet is data can be authenticated by group key nad MIC. Security enforsment point must be handled carefully these packets */
} mlme_attr_t;

/**
 * @brief struct mlme_beacon_pending_address_spec_t Pending address specification field
 *
 * See IEEE standard 802.15.4-2006 (figure 51) for more details
 */
typedef struct mlme_beacon_pending_address_spec_s {
    unsigned short_address_count: 3;                /**< Number of short address count */
    unsigned extended_address_count: 3;             /**< Number of extended address count */
} mlme_beacon_pending_address_spec_t;

/**
 * @brief struct mlme_beacon_gts_spec_t Format of GTS specification field
 *
 * See IEEE standard 802.15.4-2006 (figure 48) for more details
 */
typedef struct mlme_beacon_gts_spec_s {
    unsigned description_count: 3;      /**< Number of GTS description count */
    unsigned gts_permit: 1;             /**< 1= GTS request accepted 0= not accepted */
} mlme_beacon_gts_spec_t;

/**
 * @brief struct mlme_set_t Set request structure
 *
 * See IEEE standard 802.15.4-2006 (table 70) for more details
 */
typedef struct mlme_set_s {
    mlme_attr_t attr;           /**<PIB attribute for operation*/
    uint8_t attr_index;         /**< attribute index to to table (use only for PIB attributes which are tables)*/
    const void *value_pointer;  /**< Pointer to value*/
    uint8_t value_size;         /**< define data length in bytes behind pointer*/
} mlme_set_t;

/**
 * @brief struct mlme_get_t Get request structure
 *
 * See IEEE standard 802.15.4-2006 (table 56) for more details
 */
typedef struct mlme_get_s {
    mlme_attr_t attr;       /**<PIB attribute for operation*/
    uint8_t attr_index;     /**< attribute index to to table (use only for PIB attributes which are tables)*/
} mlme_get_t;

/**
 * @brief struct mlme_get_conf_t Get confirm structure
 *
 * See IEEE standard 802.15.4-2006 (table 57) for more details
 */
typedef struct mlme_get_conf_s {
    uint8_t status;             /**< status of operation*/
    mlme_attr_t attr;           /**<PIB attribute for operation*/
    uint8_t attr_index;         /**< attribute index to to table (valid only for PIB attributes which are tables)*/
    void *value_pointer;        /**< Pointer to data when status is MLME_SUCCESS */
    uint8_t value_size;         /**< define data length in bytes behind pointer*/
} mlme_get_conf_t;

/**
 * @brief struct mlme_set_conf_t Set confirm structure
 *
 * See IEEE standard 802.15.4-2006 (table 71) for more details
 */
typedef struct mlme_set_conf_s {
    uint8_t status;         /**< status of operation*/
    mlme_attr_t attr;       /**<PIB attribute for operation*/
    uint8_t attr_index;     /**< attribute index to to table (valid only for PIB attributes which are tables)*/
} mlme_set_conf_t;


#define MLME_MAC_RES_SIZE_MAX 16 /**< Mac scan response max supported list size */

/**
 * @brief struct mlme_reset_t Reset request structure
 *
 * See IEEE standard 802.15.4-2006 (table 63) for more details
 */
typedef struct mlme_reset_s {
    bool SetDefaultPIB; /**< true= Set standard default values, false= Mac sub layer will be reset but it retain configured MAC PIB values */
} mlme_reset_t;

/**
 * @brief struct mlme_reset_conf_t Reset confirm structure
 *
 * See IEEE standard 802.15.4-2006 (table 64) for more details
 */
typedef struct mlme_reset_conf_s {
    uint8_t status; /**< Status of reset operation */
} mlme_reset_conf_t;

/**
 * @brief struct mlme_rx_enable_t Rx enable request structure (Not supported)
 *
 * See IEEE standard 802.15.4-2006 (table 65) for more details
 */
typedef struct mlme_rx_enable_s {
    bool DeferPermit;               /**< This will be ignored at nonbeacon-enabled PAN*/
    uint32_t RxOnTime;              /**< This will be ignored at nonbeacon-enabled PAN*/
    uint32_t RxOnDuration;          /**< Number of symbols which receiver is enabled, 0 receiver is not disabled*/
} mlme_rx_enable_t;

/**
 * @brief struct mlme_rx_enable_conf_t Rx enable confirm structure (Not supported)
 *
 * See IEEE standard 802.15.4-2006 (table 66) for more details
 */
typedef struct mlme_rx_enable_conf_s {
    uint8_t status;                     /**< Status of operation */
} mlme_rx_enable_conf_t;

/**
 * @brief struct mlme_comm_status_t Comm status indication structure
 *
 * See IEEE standard 802.15.4-2006 (table 69) for more details
 */
typedef struct mlme_comm_status_s {
    uint16_t PANId;                 /**< Messages Pan-id */
    unsigned SrcAddrMode: 2;        /**< source address mode: MAC_ADDR_MODE_NONE,MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t SrcAddr[8];             /**< source address when mode is: MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    unsigned DstAddrMode: 2;        /**< destination address mode: MAC_ADDR_MODE_NONE,MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t DstAddr[8];             /**< Destination address when mode is: MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t status;                 /**< Communication status */
    mlme_security_t Key;            /**< Messages Security parameters */
} mlme_comm_status_t;

/**
 * @brief struct mlme_start_t Start request structure
 *
 * See IEEE standard 802.15.4-2006 (table 72) for more details
 */
typedef struct mlme_start_s {
    uint16_t PANId;                     /**< Pan-id */
    uint8_t LogicalChannel;             /**< Operated Logical channel */
    uint8_t ChannelPage;                /**< Operated Logical channel page */
    uint32_t StartTime;                 /**< Start time,  set 0 */
    unsigned BeaconOrder: 4;            /**< Beacon order,  set 15 */
    unsigned SuperframeOrder: 4;        /**< Super frame order,  set 15 */
    bool PANCoordinator: 1;             /**< true= Enable beacon response for beacon request, false = disable beacon request responses */
    bool BatteryLifeExtension: 1;       /**< Set false */
    bool CoordRealignment: 1;           /**< Set false */
    mlme_security_t CoordRealignKey;    /**< Coordinator Realignment security parameter's  (Valid only CoordRealignment = true)*/
    mlme_security_t BeaconRealignKey;   /**< Beacon realign security parameter's (Valid only CoordRealignment = true)*/
} mlme_start_t;

/**
 * @brief struct mlme_start_conf_t Start confirm structure (Currently not triggered yet)
 *
 * See IEEE standard 802.15.4-2006 (table 73) for more details
 */
typedef struct mlme_start_conf_s {
    uint8_t status;                 /**< Status for start confirmation */
} mlme_start_conf_t;

/**
 * @brief struct mlme_poll_t Poll request structure
 *
 * See IEEE standard 802.15.4-2006 (table 76) for more details
 */
typedef struct mlme_poll_s {
    unsigned CoordAddrMode: 2;  /**< coordinator address mode:MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint16_t CoordPANId;        /**< coordinator Pan-id to coordinator*/
    uint8_t CoordAddress[8];    /**< coordinator address */
    mlme_security_t Key;        /**< Security parameters for Poll request */
} mlme_poll_t;

/**
 * @brief struct mlme_poll_conf_t Poll confirm structure
 *
 * See IEEE standard 802.15.4-2006 (table 77) for more details
 */
typedef struct mlme_poll_conf_s {
    uint8_t status;             /**< Status of Poll operation */
} mlme_poll_conf_t;

/**
 * @brief struct mlme_multi_csma_ca_param_s Set multi CSMA-CA parameters
 *
 * Non standard extension to perform CCA multiple times before transmission
 */
typedef struct mlme_multi_csma_ca_s {
    uint8_t number_of_csma_ca_periods;  /**< Number of CSMA-CA periods */
    uint16_t multi_cca_interval;        /**< Length of the additional CSMA-CA period(s) in microseconds */
} mlme_multi_csma_ca_param_t;

/**
 * @brief struct mlme_request_restart_config_s Set failed packet request restart configuration
 *
 * Non standard extension to restart data request after failed CCA or TX attempts
 */
typedef struct mlme_request_restart_config_s {
    uint8_t cca_failure_restart_max;    /**< Max number of restarts after CCA failure */
    uint8_t tx_failure_restart_max;     /**< Max number of restarts after TX failure */
    uint16_t blacklist_min_ms;          /**< Blacklist min, which is doubled by every restart */
    uint16_t blacklist_max_ms;          /**< Blacklist max, largest allowed blacklist time */
} mlme_request_restart_config_t;

/**
 * Represents payload of MAC filter start request.
 */
typedef struct mlme_request_mac_filter_start_s {
    int16_t lqi_m;
    int16_t lqi_add;
    int16_t dbm_m;
    int16_t dbm_add;
} mlme_request_mac_filter_start_t;

/**
 * Represents payload of MAC filter add long request.
 */
typedef struct mlme_request_mac_filter_add_long_s {
    uint8_t mac64[8];
    int16_t lqi_m;
    int16_t lqi_add;
    int16_t dbm_m;
    int16_t dbm_add;
} mlme_request_mac_filter_add_long_t;

#endif /* MLME_H_ */
