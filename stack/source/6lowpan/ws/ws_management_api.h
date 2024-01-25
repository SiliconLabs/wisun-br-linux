/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
 * \file ws_management_api.h
 * \brief Wi-SUN management interface.
 *
 * This interface is used for configuring Wi-SUN devices.
 * After creating the Wi-SUN interface, you can use this interface to configure the Wi-SUN device
 * behaviour. When you are done with the configurations, you need to call interface up to enable a Wi-SUN node.
 *
 */
#ifndef WS_MANAGEMENT_API_H_
#define WS_MANAGEMENT_API_H_
#include <stdint.h>
#include "common/int24.h"

#define OPERATING_MODE_1a 0x1a  /**< 50, 0,5 */
#define OPERATING_MODE_1b 0x1b  /**< 50, 1.0 */
#define OPERATING_MODE_2a 0x2a  /**< 100, 0,5 */
#define OPERATING_MODE_2b 0x2b  /**< 100, 1.0 */
#define OPERATING_MODE_3  0x03  /**< 150, 0.5 */
#define OPERATING_MODE_4a 0x4a  /**< 200, 0.5 */
#define OPERATING_MODE_4b 0x4b  /**< 200, 1.0 */
#define OPERATING_MODE_5  0x05  /**< 300, 0.5 */

/*
 *  Network Size definitions are device amount in hundreds of devices.
 *  These definitions are meant to give some estimates of sizes. Any value can be given as parameter
 */

#define NETWORK_SIZE_CERTIFICATE    0x00    /**< Network configuration used in Wi-SUN certification */
#define NETWORK_SIZE_SMALL          0x01    /**< Small networks */
#define NETWORK_SIZE_MEDIUM         0x08    /**< 100 - 800 device networks are medium sized */
#define NETWORK_SIZE_LARGE          0x0F    /**< 800 - 1500 device networks are large */
#define NETWORK_SIZE_XLARGE         0x19    /**< 2500+ devices */
#define NETWORK_SIZE_AUTOMATIC      0xFF    /**< Automatic network size */

/**
 * Initialize Wi-SUN stack.
 *
 * Generates the default configuration for Wi-SUN operation
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain Mandatory regulatory domain value of the device.
 * \param network_name_ptr Network name where to join if no configuration found from storage.
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_node_init(
    int8_t interface_id,
    uint8_t regulatory_domain,
    char *network_name_ptr);

/**
 * Set domain configuration of Wi-SUN stack.
 *
 * Change the default configuration for Wi-SUN PHY operation.
 *
 * Supported values:
 *     Regulatory domain: "NA"(0x01), "KR"(0x09), "EU"(0x03), "IN"(0x05), "BZ"(0x07), "JP"(0x09), "WW"(0x00)
 *
 *     PHY mode ID:
 *         FSK without FEC:
 *         PHY mode ID | Symbol Rate (kbps) | Modulation Index
 *                   1                   50                0.5
 *                   2                   50                1.0
 *                   3                  100                0.5
 *                   4                  100                1.0
 *                   5                  150                0.5
 *                   6                  200                0.5
 *                   7                  200                1.0
 *                   8                  300                0.5
 *
 *         FSK with FEC:
 *         PHY mode ID | Symbol Rate (kbps) | Modulation Index
 *                  17                   50                0.5
 *                  18                   50                1.0
 *                  19                  100                0.5
 *                  20                  100                1.0
 *                  21                  150                0.5
 *                  22                  200                0.5
 *                  23                  200                1.0
 *                  24                  300                0.5
 *
 *         OFDM:
 *         PHY mode ID | Option | MCS | Data rate (kbps)
 *                  34        1     2                400
 *                  35        1     3                800
 *                  36        1     4               1200
 *                  37        1     5               1600
 *                  38        1     6               2400
 *                  51        2     3                400
 *                  52        2     4                600
 *                  53        2     5                800
 *                  54        2     6               1200
 *                  68        3     4                300
 *                  69        3     5                400
 *                  70        3     6                600
 *                  84        4     4                150
 *                  85        4     5                200
 *                  86        4     6                300
 *
 *     Channel plan ID:
 *         North America (NA):  (1), (2), (5)
 *         Brazil (BZ):         (1), (2), (5)
 *
 * If value of 0 is given then previous value is used.
 * If value of 255 is given then default value is used.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain Regulatory domain.
 * \param phy_mode_id PHY mode ID.
 * \param channel_plan_id Channel plan ID.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_domain_configuration_set(
    int8_t interface_id,
    uint8_t regulatory_domain,
    uint8_t phy_mode_id,
    uint8_t channel_plan_id);

/**
 * Get domain configuration of Wi-SUN stack.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain Regulatory domain.
 * \param phy_mode_id PHY mode ID.
 * \param channel_plan_id Channel plan ID.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_domain_configuration_get(
    int8_t interface_id,
    uint8_t *regulatory_domain,
    uint8_t *phy_mode_id,
    uint8_t *channel_plan_id);

/**
 * Validate domain configuration of Wi-SUN stack.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain Regulatory domain.
 * \param phy_mode_id PHY mode ID.
 * \param channel_plan_id Channel plan ID.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_domain_configuration_validate(
    int8_t interface_id,
    uint8_t regulatory_domain,
    uint8_t phy_mode_id,
    uint8_t channel_plan_id);

/**
 * Configure regulatory domain of Wi-SUN stack.
 *
 * Change the default configuration for Wi-SUN PHY operation.
 *
 * Supported values:
 * Domain: "NA"(0x01), "KR"(0x09), "EU"(0x03), "IN"(0x05), "KR"(0x09), "JP"(0x09), "WW"(0x00)
 * Operating class: (1), (2), (3), (4)
 * Operation mode: "1a" (symbol rate 50, modulation index 0.5)
 *                 "1b" (symbol rate 50, modulation index 1.0)
 *                 "2a" (symbol rate 100, modulation index 0.5)
 *                 "2b" (symbol rate 100, modulation index 1.0)
 *                 "3"  (symbol rate 150, modulation index 0.5)
 *                 "4a" (symbol rate 200, modulation index 0.5)
 *                 "4b" (symbol rate 200, modulation index 1.0)
 *                 "5"  (symbol rate 300, modulation index 0.5)
 *
 * if value of 255 is given then previous value is used.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain FHSS regulatory domain. Default to "EU" 0x03.
 * \param operating_class FHSS operating class. Default to 2.
 * \param operating_mode FHSS phy operating mode. Default to "3".
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_regulatory_domain_set(
    int8_t interface_id,
    uint8_t regulatory_domain,
    uint8_t operating_class,
    uint8_t operating_mode,
    uint8_t phy_mode_id,
    uint8_t channel_plan_id);

/**
 * Get regulatory domain of Wi-SUN stack.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain FHSS regulatory domain.
 * \param operating_class FHSS operating class.
 * \param operating_mode FHSS phy operating mode.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_regulatory_domain_get(
    int8_t interface_id,
    uint8_t *regulatory_domain,
    uint8_t *operating_class,
    uint8_t *operating_mode);

/**
 * Validate regulatory domain of Wi-SUN stack.
 *
 * \param interface_id Network interface ID.
 * \param regulatory_domain FHSS regulatory domain.
 * \param operating_class FHSS operating class.
 * \param operating_mode FHSS phy operating mode.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_regulatory_domain_validate(
    int8_t interface_id,
    uint8_t regulatory_domain,
    uint8_t operating_class,
    uint8_t operating_mode);

/**
 * Set timing parameters related to network size.
 *
 * timing parameters follows the specification example from Wi-SUN specification
 *
 * Default value: medium 100 - 800 device
 * small network size: less than 100 devices
 * Large network size: 800 - 1500 devices
 * automatic: when discovering the network network size is learned
 *            from advertisements and timings adjusted accordingly
 *
 * When network size is changed, it will override following configuration values:
 * - Timing settings set by ws_management_timing_parameters_set()
 *
 * If values should be other than defaults set by stack, they need to set using
 * above function calls after network size change.
 *
 * \param interface_id Network interface ID.
 * \param network_size Network size in hundreds of devices, certificate or automatic.
 *                     See NETWORK_SIZE_ definition.
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_network_size_set(
    int8_t interface_id,
    uint8_t network_size);

/**
 * Get timing parameters related to network size.
 *
 * \param interface_id Network interface ID.
 * \param network_size Network size in hundreds of devices, certificate or automatic.
 *                     See NETWORK_SIZE_ definition.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_network_size_get(
    int8_t interface_id,
    uint8_t *network_size);

/**
 * Validate timing parameters related to network size.
 *
 * \param interface_id Network interface ID.
 * \param network_size Network size in hundreds of devices, certificate or automatic.
 *                     See NETWORK_SIZE_ definition.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_network_size_validate(
    int8_t interface_id,
    uint8_t network_size);

/**
 * Set channel mask for FHSS operation.
 *
 * Default value: all channels are allowed.
 *
 * \param interface_id Network interface ID.
 * \param channel_mask set bits matching the channel 1 to allow channel 0 to disallow.
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_channel_mask_set(
    int8_t interface_id,
    uint8_t channel_mask[32]);

/**
 * Get channel mask for FHSS operation.
 *
 * \param interface_id Network interface ID.
 * \param channel_mask set bits matching the channel 1 to allow channel 0 to disallow.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_channel_mask_get(
    int8_t interface_id,
    uint8_t *channel_mask);

/**
 * Validate channel mask for FHSS operation.
 *
 * \param interface_id Network interface ID.
 * \param channel_mask set bits matching the channel 1 to allow channel 0 to disallow.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_channel_mask_validate(
    int8_t interface_id,
    uint32_t channel_mask[8]);

/**
 * Configure Application defined channel plan.
 *
 * Change the application defined channel plan.
 * This changes our channel plan that is reported to our children.
 * PHY driver must be configured to follow these settings to make the configuration active.
 *
 *
 * \param interface_id Network interface ID.
 * \param uc_channel_function 0: Fixed channel, 1:TR51CF, 2: Direct Hash, 3: Vendor defined.
 * \param bc_channel_function 0: Fixed channel, 1:TR51CF, 2: Direct Hash, 3: Vendor defined.
 * \param ch0_freq ch0 center frequency in Hz
 * \param channel_spacing Channel spacing value 0:200k, 1:400k, 2:600k, 3:100k.
 * \param number_of_channels FHSS phy operating mode default to "1b".
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_channel_plan_set(
    int8_t interface_id,
    uint8_t uc_channel_function,
    uint8_t bc_channel_function,
    uint32_t ch0_freq, // Stack can not modify this
    uint32_t channel_spacing,// Stack can not modify this
    uint8_t number_of_channels);// Stack can not modify this

/**
 * Configure unicast channel function.
 *
 * Change the default configuration for Wi-SUN FHSS operation.
 * if application defined is used the behaviour is undefined
 *
 * Calling with dwell_interval = 0, channel_function = 0xff, fixed_channel = 0xffff restores stack defaults
 *
 * \param interface_id Network interface ID.
 * \param channel_function Unicast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Used dwell interval when channel function is TR51 or DH1.
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_fhss_unicast_channel_function_configure(
    int8_t interface_id,
    uint8_t channel_function,
    uint16_t fixed_channel,
    uint8_t dwell_interval);

/**
 * Get unicast channel function.
 *
 * \param interface_id Network interface ID.
 * \param channel_function Unicast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Used dwell interval when channel function is TR51 or DH1.
 *
 * \return 0, OK.
 * \return <0 fail.
 */
int ws_management_fhss_unicast_channel_function_get(
    int8_t interface_id,
    uint8_t *channel_function,
    uint16_t *fixed_channel,
    uint8_t *dwell_interval);

/**
 * Validate unicast channel function.
 *
 * \param interface_id Network interface ID.
 * \param channel_function Unicast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Used dwell interval when channel function is TR51 or DH1.
 *
 * \return 0, OK.
 * \return <0 fail.
 */
int ws_management_fhss_unicast_channel_function_validate(
    int8_t interface_id,
    uint8_t channel_function,
    uint16_t fixed_channel,
    uint8_t dwell_interval);

/**
 * Configure broadcast channel function.
 *
 * Change the default configuration for Wi-SUN FHSS operation.
 * if application defined is used the behaviour is undefined
 *
 * Calling with dwell_interval = 0, channel_function = 0xff,
 * broadcast_interval = 0xffffffff, fixed_channel = 0xffff restores stack defaults
 *
 * \param interface_id Network interface ID.
 * \param channel_function Broadcast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Broadcast channel dwell interval.
 * \param broadcast_interval Broadcast interval.
 *
 * \return 0, Init OK.
 * \return <0 Init fail.
 */
int ws_management_fhss_broadcast_channel_function_configure(
    int8_t interface_id,
    uint8_t channel_function,
    uint16_t fixed_channel,
    uint8_t dwell_interval,
    uint32_t broadcast_interval);

/**
 * Get broadcast channel function.
 *
 * \param interface_id Network interface ID.
 * \param channel_function Broadcast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Broadcast channel dwell interval.
 * \param broadcast_interval Broadcast interval.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_fhss_broadcast_channel_function_get(
    int8_t interface_id,
    uint8_t *channel_function,
    uint16_t *fixed_channel,
    uint8_t *dwell_interval,
    uint32_t *broadcast_interval);

/**
 * Validate broadcast channel function.
 *
 * \param interface_id Network interface ID.
 * \param channel_function Broadcast channel function.
 * \param fixed_channel Used channel when channel function is fixed channel.
 * \param dwell_interval Broadcast channel dwell interval.
 * \param broadcast_interval Broadcast interval.
 *
 * \return 0, OK.
 * \return <0 Fail.
 */
int ws_management_fhss_broadcast_channel_function_validate(
    int8_t interface_id,
    uint8_t channel_function,
    uint16_t fixed_channel,
    uint8_t dwell_interval,
    uint32_t broadcast_interval);

int ws_management_fhss_lfn_configure(int8_t if_id,
                                     uint24_t lfn_bc_interval,
                                     uint8_t lfn_bc_sync_period);

#endif
