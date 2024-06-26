/*
 * Copyright (c) 2018, 2021, Pelion and affiliates.
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

#ifndef MPX_API_H_
#define MPX_API_H_
#include <stdint.h>
#include <stdbool.h>
#include "app/rcp_api_legacy.h"

struct mcps_data_req;
struct mcps_data_cnf;
struct mcps_data_ind;
struct mcps_purge;

typedef struct mpx_api mpx_api_t;

/**
 * @brief mpx_data_request MPX_DATA request with user ID
 * @param api API to handle the request
 * @param data MCPS-DATA.request specific values
 * @param user_id MPX user ID
 * @param priority priority level
 *
 */
typedef void mpx_data_request(const mpx_api_t *api, const struct mcps_data_req *data, uint16_t user_id);

/**
 * @brief mpx_data_confirm MPX-DATA confirm is called as a response to MPX-DATA request
 * @param api The API which handled the response
 * @param data MCPS-DATA.confirm specific values
 * @param user_id MPX user ID
 */
typedef void mpx_data_confirm(const mpx_api_t *api, const struct mcps_data_cnf *data);

/**
 * @brief mpx_data_indication MPX-DATA confirm is called as a response to MPX-DATA request
 * @param api The API which handled the response
 * @param data MCPS-DATA.indication specific values
 * @param user_id MPX user ID
 */
typedef void mpx_data_indication(const mpx_api_t *api, const struct mcps_data_ind *data);

/**
 * @brief mpx_header_size_get Function for request MPX user head room size
 * @param api The API which handled the response
 * @param user_id MPX user ID
 *
 * @return >0 Head room size in bytes
 * @return 0 When Unknown User Id
 */
typedef uint16_t mpx_header_size_get(const mpx_api_t *api, uint16_t user_id);

/**
 * @brief mpx_data_cb_register MPX-DATA confirm cb register by user
 * @param api The API which handled the response
 * @param confirm_cb MPX Data Confirm call back
 * @param indication_cb MPX Data indication
 * @param user_id MPX user ID
 *
 * @return 0 register OK
 * @return -1 Unknown User ID
 */
typedef int8_t mpx_data_cb_register(const mpx_api_t *api, mpx_data_confirm *confirm_cb, mpx_data_indication *indication_cb, uint16_t user_id);

/**
 * \brief Struct mpx_api_s defines functions for MPX user for register call backs and send data.
 */
struct mpx_api {
    mpx_data_request *mpx_data_request;             /**< MPX data request. */
    mpx_header_size_get *mpx_headroom_size_get;     /**< MPX headroom size get in bytes. */
    mpx_data_cb_register *mpx_user_registration;    /**< MPX User cb registration must be call before enable to send or RX data*/
};


#endif
