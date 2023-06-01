/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "common/rand.h"
#include "common/log_legacy.h"
#include "common/endian.h"

#include "dhcpv6_utils.h"

#define TRACE_GROUP "dhcp"

static NS_LIST_DEFINE(dhcpv6_client_nonTemporal_list, dhcpv6_client_server_data_t, link);

//Allocate
static dhcpv6_client_server_data_t *libdhcvp6_nontemporalAddress_entry_allocate(void)
{
    dhcpv6_client_server_data_t *newEntry = malloc(sizeof(dhcpv6_client_server_data_t));
    uint8_t *temporary_duid = malloc(16); //Support DUID-LL, DUID-LLP and DUID-UUID  by default
    if (!newEntry || !temporary_duid) {
        free(newEntry);
        free(temporary_duid);
        return NULL;
    }

    newEntry->T0 = 0;
    newEntry->T1 = 0;
    newEntry->reNewTimer = 0;
    newEntry->iaNonTemporalStructValid = false;
    newEntry->GlobalAddress = false;
    newEntry->useServerAddress = false;
    newEntry->iaNontemporalAddress.preferredTime = 0;
    newEntry->iaNontemporalAddress.validLifetime = 0;
    newEntry->dyn_server_duid_length = 16;
    newEntry->serverDynamic_DUID = temporary_duid;
    return newEntry;
}

static uint32_t libdhcpv6_IAID_generate(void)
{
    uint32_t iaId;
    bool notUnique = true;
    while (notUnique) {
        notUnique = false;
        iaId = rand_get_32bit();
        if (libdhcpv6_nonTemporal_entry_get_by_iaid(iaId)) {
            notUnique = true;
        }

    }
    return iaId;
}

static uint32_t libdhcpv6_Tx_timer_generate(uint32_t lifetime, bool T1_get)
{
    uint32_t timeout = lifetime;

    if (T1_get) {
        timeout = (timeout >> 1);
    } else {
        timeout = (timeout >> 2);
        timeout = (timeout * 3);
    }

    return timeout;
}

uint32_t libdhcpv6_txid_get(void)
{
    uint32_t transaction_id = rand_get_32bit();
    transaction_id &= 0x00ffffff;
    return transaction_id;
}

uint32_t libdhcpv6_renew_time_define(dhcpv6_client_server_data_t *addresInfo)
{
    uint32_t renewTimer = 0xffffffff;

    if (addresInfo->iaNontemporalAddress.preferredTime < renewTimer) {
        renewTimer = addresInfo->iaNontemporalAddress.preferredTime;
    }

    if (renewTimer ==  0xffffffff) {
        //Check T1
        renewTimer = 0;
    } else if (renewTimer < 100) {
        renewTimer = 100;
    }

    if (addresInfo->T0 == 0) {
        //Calculate
        if (renewTimer != 0) {
            addresInfo->T0 = libdhcpv6_Tx_timer_generate(renewTimer, true);
            addresInfo->T1 = libdhcpv6_Tx_timer_generate(renewTimer, false);
        } else {
            addresInfo->T0 = 0xffffffff;
            addresInfo->T1 = 0xffffffff;
        }
    }

    //Calculate Renew Time
    if (addresInfo->T0 != 0xffffffff) {
        renewTimer = addresInfo->T0;
    } else {
        renewTimer = 0;
    }

    return renewTimer;
}

dhcpv6_client_server_data_t *libdhcvp6_nontemporalAddress_server_data_allocate(int8_t interfaceId, uint8_t instanceId, uint8_t *nonTemporalPrefix, uint8_t *serverIPv6Address)
{
    uint32_t iaId;
    uint8_t *ptr;
    dhcpv6_client_server_data_t *new_entry = NULL;
    //allocate new Entry
    iaId = libdhcpv6_IAID_generate();
    new_entry = libdhcvp6_nontemporalAddress_entry_allocate();
    if (new_entry) {
        new_entry->IAID = iaId;
        new_entry->interfaceId = interfaceId;
        new_entry->instanceId = instanceId;
        new_entry->serverDUID.duid = NULL;
        new_entry->serverDUID.duid_length = 0;

        if (serverIPv6Address) {
            memcpy(new_entry->server_address, serverIPv6Address, 16);
            new_entry->useServerAddress = true;
        }
        if (nonTemporalPrefix) {
            ptr = new_entry->iaNontemporalAddress.addressPrefix;
            memcpy(ptr, nonTemporalPrefix, 8);
            memset((ptr + 8), 0, 8);
            new_entry->iaNonTemporalStructValid = true;
            new_entry->iaNontemporalAddress.preferredTime = 0;
            new_entry->iaNontemporalAddress.validLifetime = 0;
        }
        ns_list_add_to_end(&dhcpv6_client_nonTemporal_list, new_entry);
    }
    return new_entry;
}

void libdhcvp6_nontemporalAddress_server_data_free(dhcpv6_client_server_data_t *removedEntry)
{
    if (removedEntry) {
        ns_list_remove(&dhcpv6_client_nonTemporal_list, removedEntry);
        free(removedEntry->serverDynamic_DUID);
        free(removedEntry);
    }
}

dhcpv6_client_server_data_t *libdhcpv6_nonTemporal_entry_get_by_instance(uint8_t instanceId)
{
    ns_list_foreach(dhcpv6_client_server_data_t, cur, &dhcpv6_client_nonTemporal_list) {
        if (cur->instanceId == instanceId) {
            return cur;
        }
    }
    return NULL;
}
uint8_t libdhcpv6_nonTemporal_entry_get_unique_instance_id(void)
{
    uint8_t unique_id = 1;
    ns_list_foreach(dhcpv6_client_server_data_t, cur, &dhcpv6_client_nonTemporal_list) {
        if (cur->instanceId == unique_id) {
            unique_id++;
            cur = ns_list_get_first(&dhcpv6_client_nonTemporal_list);
        }
    }
    return unique_id;
}

dhcpv6_client_server_data_t *libdhcpv6_nonTemporal_entry_get_by_iaid(uint32_t iaId)
{
    ns_list_foreach(dhcpv6_client_server_data_t, cur, &dhcpv6_client_nonTemporal_list) {
        if (cur->IAID == iaId) {
            return cur;
        }
    }
    return NULL;
}

dhcpv6_client_server_data_t *libdhcpv6_nonTemporal_entry_get_by_prefix(int8_t interfaceId, uint8_t *prefix)
{
    ns_list_foreach(dhcpv6_client_server_data_t, cur, &dhcpv6_client_nonTemporal_list) {
        if (cur->interfaceId == interfaceId) {
            if (memcmp(cur->iaNontemporalAddress.addressPrefix, prefix, 8) == 0) {
                return cur;
            }
        }
    }
    return NULL;
}

dhcpv6_client_server_data_t *libdhcpv6_nonTemporal_validate_class_pointer(void *class_ptr)
{
    ns_list_foreach(dhcpv6_client_server_data_t, cur, &dhcpv6_client_nonTemporal_list) {
        if (cur == class_ptr) {
            return cur;
        }
    }
    return NULL;
}

uint16_t libdhcpv6_duid_option_size(uint16_t duidLength)
{
    return duidLength + 6; //ID Type 2, length 2 ,Duid Type 2 + duid data
}

uint8_t libdhcpv6_duid_linktype_size(uint16_t linkType)
{
    if (linkType == DHCPV6_DUID_HARDWARE_EUI64_TYPE ||
            linkType == DHCPV6_DUID_HARDWARE_IEEE_802_NETWORKS_TYPE) {
        return 8;
    }

    return 6;
}

uint16_t libdhcvp6_request_option_size(uint8_t optionCnt)
{
    uint16_t optionLength = 4;
    optionLength += 2 * optionCnt;
    return optionLength;
}

uint16_t libdhcpv6_non_temporal_address_size(bool addressDefined)
{
    uint16_t optionLength = 16;
    if (addressDefined) {
        optionLength += libdhcpv6_ia_address_option_size();
    }
    return optionLength;
}

int libdhcpv6_message_malformed_check(uint8_t *ptr, uint16_t data_len)
{
    uint8_t *dptr;
    uint16_t length;
    if (data_len > 4) {
        dptr = ptr + 4; //Skip Type & TXID
        data_len -= 4;
        while (data_len) {
            if (data_len >= 4) {

                length = read_be16(dptr + 2); //Skip Type
                dptr += 4;
                data_len -= 4;
                if (data_len >= length) {
                    data_len -= length;
                    dptr += length;
                }
            } else {
                return -1;
            }
        }
    }
    return 0;
}


/**
 * This Function write dhcpv6 basic header
 *
 * \param ptr pointer where header will be writed
 * \param msgType dhcpv6 message type
 * \param transActionId 24-bit unique Trasnaction ID
 *
 * return incremented pointer after write
 */
uint8_t *libdhcpv6_header_write(uint8_t *ptr, uint8_t msgType, uint32_t transActionId)
{
    *ptr++ = msgType;
    ptr = write_be24(ptr, transActionId);
    return ptr;
}

uint8_t *libdhcpv6_elapsed_time_option_write(uint8_t *ptr, uint16_t elapsedTime)
{
    //Elapsed time
    ptr = write_be16(ptr, DHCPV6_ELAPSED_TIME_OPTION);
    ptr = write_be16(ptr, DHCPV6_ELAPSED_TIME_OPTION_LEN);
    ptr = write_be16(ptr, elapsedTime);
    return ptr;
}

uint8_t *libdhcpv6_rapid_commit_option_write(uint8_t *ptr)
{
    ptr = write_be16(ptr, DHCPV6_OPTION_RAPID_COMMIT);
    ptr = write_be16(ptr, DHCPV6_OPTION_RAPID_COMMIT_LEN);
    return ptr;
}

uint8_t *libdhcvp6_request_option_write(uint8_t *ptr, uint8_t optionCnt, uint16_t *optionPtr)
{
    uint16_t optionLength = libdhcvp6_request_option_size(optionCnt);
    ptr = write_be16(ptr, DHCPV6_OPTION_REQUEST_OPTION);
    ptr = write_be16(ptr, (optionLength - 4));
    while (optionCnt) {
        ptr = write_be16(ptr, *optionPtr++);
        optionCnt--;
    }
    return ptr;
}

uint8_t *libdhcpv6_duid_option_write(uint8_t *ptr, uint16_t duidRole, const dhcp_duid_options_params_t *duid)
{
    uint16_t length = duid->duid_length + 2;
    ptr = write_be16(ptr, duidRole);
    ptr = write_be16(ptr, length);
    ptr = write_be16(ptr, duid->type);
    memcpy(ptr, duid->duid, duid->duid_length);
    ptr += duid->duid_length;
    return ptr;
}

uint8_t *libdhcpv6_identity_association_option_write(uint8_t *ptr, uint32_t iaID, uint32_t TimerT1, uint32_t TimerT2, bool withAddress)
{
    uint16_t optionMsgLen = libdhcpv6_non_temporal_address_size(withAddress);

    ptr = write_be16(ptr, DHCPV6_IDENTITY_ASSOCIATION_OPTION);
    ptr = write_be16(ptr, (optionMsgLen - 4));

    ptr = write_be32(ptr, iaID); //iaId
    ptr = write_be32(ptr, TimerT1); //T1
    ptr = write_be32(ptr, TimerT2);//T2
    return ptr;
}

uint8_t *libdhcpv6_ia_address_option_write(uint8_t *ptr, const uint8_t *addressPtr, uint32_t preferredValidLifeTime, uint32_t validLifeTime)
{
    ptr = write_be16(ptr, DHCPV6_IA_ADDRESS_OPTION);
    ptr = write_be16(ptr, DHCPV6_IA_ADDRESS_OPTION_LEN);
    memcpy(ptr, addressPtr, 16);
    ptr += 16;
    ptr = write_be32(ptr, preferredValidLifeTime); //Preferred
    ptr = write_be32(ptr, validLifeTime);//Valid
    return ptr;
}

uint8_t *libdhcpv6_status_code_write(uint8_t *ptr, uint16_t statusCode)
{
    ptr = write_be16(ptr, DHCPV6_STATUS_CODE_OPTION);
    ptr = write_be16(ptr, DHCPV6_STATUS_CODE_OPTION_LEN);
    ptr = write_be16(ptr, statusCode);
    return ptr;
}

uint8_t *libdhcpv6_client_last_transaction_time_option_write(uint8_t *ptr, uint32_t last_transaction_Time)
{

    uint16_t Length = libdhcpv6_client_last_transaction_time_option_size();
    ptr = write_be16(ptr, DHCPV6_OPTION_CLT_TIME);
    ptr = write_be16(ptr, (Length - 4));
    ptr = write_be32(ptr, last_transaction_Time); //SET Last time we heard from this child either from mle or data packets.
    return ptr;
}

int libdhcpv6_message_option_discover(uint8_t *ptr, uint16_t data_len, uint16_t discovered_type, dhcp_options_msg_t *option_info)
{
    uint8_t *dptr;
    uint16_t type, length;
    dptr = ptr;
    if (data_len < 4) {
        tr_warn("libdhcpv6_message_option_discover() data_len<4");
        return -1;
    }
    while (data_len >= 4) {
        type = read_be16(dptr);
        dptr += 2;
        length = read_be16(dptr);
        dptr += 2;
        data_len -= 4;
        if (data_len >= length) {
            if (type == discovered_type) {
                option_info->len = length;
                option_info->type = type;
                option_info->msg_ptr = dptr;
                return 0;
            }
            data_len -= length;
            dptr += length;
        } else {
            tr_warn("libdhcpv6_message_option_discover() data_len<length=%"PRIu16, length);
            break;
        }
    }
    return -1;
}

int libdhcpv6_compare_DUID(dhcp_duid_options_params_t *targetId, dhcp_duid_options_params_t *parsedId)
{
    if (targetId->type != parsedId->type) {
        return -1;
    }

    if (targetId->duid_length != parsedId->duid_length) {
        return -1;
    }

    if (memcmp(targetId->duid, parsedId->duid, targetId->duid_length) != 0) {
        return -1;
    }
    return 0;
}

int libdhcpv6_reply_message_option_validate(dhcp_duid_options_params_t *clientId, dhcp_duid_options_params_t *serverId, dhcp_ia_non_temporal_params_t *dhcp_ia_non_temporal_params, uint8_t *ptr, uint16_t data_length)
{
    /**
     * Solicitation Message Should Include Next Options:
     *  - DHCPV6_OPTION_RAPID_COMMIT
     *  - DHCPV6_SERVER_ID_OPTION
     *  - DHCPV6_CLIENT_ID_OPTION
     *  - DHCPV6_IDENTITY_ASSOCIATION_OPTION
     *
     */
    /** Verify Client ID */
    if (libdhcpv6_get_duid_by_selected_type_id_opt(ptr, data_length, DHCPV6_CLIENT_ID_OPTION, clientId) != 0) {
        return -1;
    }

    if (libdhcpv6_get_duid_by_selected_type_id_opt(ptr, data_length, DHCPV6_SERVER_ID_OPTION, serverId) != 0) {
        return -1;
    }

    if (!libdhcpv6_rapid_commit_option_at_packet(ptr, data_length)) {
        return -1;
    }

    if (libdhcpv6_get_IA_address(ptr, data_length, dhcp_ia_non_temporal_params) != 0) {
        return -1;
    }

    return 0;
}

bool libdhcpv6_rapid_commit_option_at_packet(uint8_t *ptr, uint16_t length)
{
    bool retVal = false;
    dhcp_options_msg_t option_msg;
    if (libdhcpv6_message_option_discover(ptr, length, DHCPV6_OPTION_RAPID_COMMIT, &option_msg) == 0) {
        retVal = true;
    }
    return retVal;
}

bool libdhcpv6_duid_length_validate(uint16_t duid_type, uint16_t duid_length)
{
    uint16_t min_length;
    switch (duid_type) {
        case DHCPV6_DUID_LINK_LAYER_PLUS_TIME_TYPE:
            //hardware type (16 bits) + time (32 bits) +link layer address (variable length 1 min)
            min_length = 7; //Link Time Time
            break;
        case DHCPV6_DUID_EN_TYPE: //enterprise-number (32-bits) +identifier (variable length 1 min)
            min_length = 5;
            break;
        case DHCPV6_DUID_LINK_LAYER_TYPE:
            //hardware type (16 bits)  + link layer address (variable length 1 min)
            min_length = 3; //Type 2 and MiN DUI-id 1
            break;

        case DHCPV6_DUID_UUID_TYPE:
            //UUID (128-bits)
            if (duid_length != 16) {
                return false;
            }
            min_length = 16;
            break;

        default://Unsupported type set length to inpossible
            min_length = 0xffff;
            break;
    }

    //Validate min and MAX length
    if (min_length > duid_length || min_length == 0xffff) {
        //Too short
        return false;
    }

    if (duid_length > 128 - min_length) {
        //Too Long
        return false;
    }

    return true;
}


int libdhcpv6_get_duid_by_selected_type_id_opt(uint8_t *ptr, uint16_t data_length, uint16_t type, dhcp_duid_options_params_t *params)
{
    dhcp_options_msg_t option_msg;

    /** Verify DHCPV6_CLIENT_ID_OPTION */
    if (libdhcpv6_message_option_discover(ptr, data_length, type, &option_msg) != 0) {
        return -1;
    }

    if (option_msg.len < 5) {
        return -1;
    }

    uint8_t *t_ptr = option_msg.msg_ptr;
    params->type = read_be16(t_ptr);
    t_ptr += 2;
    params->duid = t_ptr;
    params->duid_length = option_msg.len - 2;
    //Validate types and lengths
    if (!libdhcpv6_duid_length_validate(params->type, params->duid_length)) {
        return -1;
    }

    return 0;
}

int libdhcpv6_get_IA_address(uint8_t *ptr, uint16_t data_length, dhcp_ia_non_temporal_params_t *params)
{
    dhcp_options_msg_t option_msg;
    uint16_t status_code = 0;

    if (libdhcpv6_message_option_discover(ptr, data_length, DHCPV6_STATUS_CODE_OPTION, &option_msg) == 0) {
        if (option_msg.len >= DHCPV6_STATUS_CODE_OPTION_LEN) {
            status_code = read_be16(option_msg.msg_ptr);
            if (status_code) {
                return -1;
            }
        }
    }

    if (libdhcpv6_message_option_discover(ptr, data_length, DHCPV6_IDENTITY_ASSOCIATION_OPTION, &option_msg) == 0) {
        if (option_msg.len < DHCPV6_IDENTITY_ASSOCIATION_OPTION_MIN_LEN) {
            return -1;
        }
        uint8_t *t_ptr;
        uint16_t length;
        t_ptr = option_msg.msg_ptr;
        length = (option_msg.len - 12);
        params->iaId = read_be32(t_ptr);
        t_ptr += 4;
        params->T0 = read_be32(t_ptr);
        t_ptr += 4;
        params->T1 = read_be32(t_ptr);
        t_ptr += 4;

        if (length > 4) {
            if (libdhcpv6_message_option_discover(t_ptr, length, DHCPV6_STATUS_CODE_OPTION, &option_msg) == 0) {
                if (option_msg.len >= DHCPV6_STATUS_CODE_OPTION_LEN) {
                    status_code = read_be16(option_msg.msg_ptr);
                    if (status_code) {
                        return -1;
                    }
                }
            }

            if (libdhcpv6_message_option_discover(t_ptr, length, DHCPV6_IA_ADDRESS_OPTION, &option_msg) == 0) {
                if (option_msg.len >= DHCPV6_IA_ADDRESS_OPTION_LEN) {
                    t_ptr = option_msg.msg_ptr;
                    params->nonTemporalAddress = t_ptr;
                    t_ptr += 16;
                    params->preferredValidLifeTime = read_be32(t_ptr);
                    t_ptr += 4;
                    params->validLifeTime = read_be32(t_ptr);
                    return 0;
                }
            }
        } else if (length == 0) {
            params->nonTemporalAddress = NULL;
            params->preferredValidLifeTime = 0;
            params->validLifeTime = 0;
            return 0;
        }
    }
    return -1;
}

uint16_t libdhcpv6_address_request_message_len(uint16_t clientDUIDLength, uint16_t serverDUIDLength, uint8_t requstOptionCnt, bool add_address)
{
    uint16_t length = 0;
    length += libdhcpv6_header_size();
    length += libdhcpv6_elapsed_time_option_size();
    length += libdhcpv6_duid_option_size(clientDUIDLength);
    if (serverDUIDLength)
        length += libdhcpv6_duid_option_size(serverDUIDLength);
    length += libdhcvp6_request_option_size(requstOptionCnt);
    length += libdhcpv6_rapid_commit_option_size();
    length += libdhcpv6_non_temporal_address_size(add_address);
    return length;
}

uint8_t *libdhcpv6_generic_nontemporal_address_message_write(uint8_t *ptr, dhcpv6_solicitation_base_packet_s *packet, dhcpv6_ia_non_temporal_address_s *nonTemporalAddress, dhcp_duid_options_params_t *serverLink)
{
    bool add_address = false;
    if (nonTemporalAddress) {
        add_address = true;
    }
    //Start Build Packet
    ptr = libdhcpv6_header_write(ptr, packet->messageType, packet->transActionId);
    //Elapsed time
    ptr = libdhcpv6_elapsed_time_option_write(ptr, 0);
    //Client Identifier
    ptr = libdhcpv6_duid_option_write(ptr, DHCPV6_CLIENT_ID_OPTION, &packet->clientDUID); //16
    //SET Server ID if It is defined
    if (serverLink) {
        ptr = libdhcpv6_duid_option_write(ptr, DHCPV6_SERVER_ID_OPTION, serverLink);
    }

    //SET Server ID
    ptr = libdhcpv6_rapid_commit_option_write(ptr);
    //Request Option
    ptr = libdhcvp6_request_option_write(ptr, packet->requestedOptionCnt, packet->requestedOptionList);
    //CLient Identity Association

    ptr = libdhcpv6_identity_association_option_write(ptr, packet->iaID, packet->timerT0, packet->timerT1, add_address);
    if (add_address) {
        ptr = libdhcpv6_ia_address_option_write(ptr, nonTemporalAddress->requestedAddress, nonTemporalAddress->preferredLifeTime, nonTemporalAddress->validLifeTime);
    }

    return ptr;
}

uint16_t libdhcpv6_solicitation_message_length(uint16_t clientDUIDLength, bool addressDefined, uint8_t requestOptionCount)
{
    uint16_t length = 0;
    length += libdhcpv6_header_size();
    length += libdhcpv6_elapsed_time_option_size();
    length += libdhcpv6_rapid_commit_option_size();
    length += libdhcpv6_duid_option_size(clientDUIDLength);
    length += libdhcpv6_non_temporal_address_size(addressDefined);
    length += libdhcvp6_request_option_size(requestOptionCount);
    return length;
}


uint8_t *libdhcpv6_dhcp_relay_msg_write(uint8_t *ptr, uint8_t type, uint8_t hop_limit,  uint8_t *peer_addres, uint8_t *link_address)
{
    *ptr++ = type;
    *ptr++ = hop_limit;
    memcpy(ptr, link_address, 16);
    ptr += 16;
    memcpy(ptr, peer_addres, 16);
    ptr += 16;
    return ptr;
}

uint8_t *libdhcpv6_dhcp_option_header_write(uint8_t *ptr, uint16_t option_type, uint16_t length)
{
    ptr = write_be16(ptr, option_type);
    ptr = write_be16(ptr, length);
    return ptr;
}

bool libdhcpv6_relay_msg_read(uint8_t *ptr, uint16_t length, dhcpv6_relay_msg_t *relay_msg)
{
    if (length < DHCPV6_RELAY_LENGTH + 4) {
        return false;
    }
    // Relay message base first
    relay_msg->type = *ptr++;
    relay_msg->hop_limit = *ptr++;
    relay_msg->link_address = ptr;
    relay_msg->peer_address = ptr + 16;
    ptr += 32;
    //Discover
    if (libdhcpv6_message_option_discover(ptr, length - 34, DHCPV6_OPTION_INTERFACE_ID, &relay_msg->relay_interface_id) != 0) {
        relay_msg->relay_interface_id.len = 0;
        relay_msg->relay_interface_id.msg_ptr = NULL;
    }

    if (libdhcpv6_message_option_discover(ptr, length - 34, DHCPV6_OPTION_RELAY, &relay_msg->relay_options) != 0) {
        return false;
    }


    return true;
}
