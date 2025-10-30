/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <ns3/sl-wisun-linux.h>
#include <sl_wisun_msg_api.h>
#include <sl_wisun_api.h>
#include <endian.h>
#include <stddef.h>
#include <string.h>

#include "tools/simulation/ncp_iface.h"
#include "tools/simulation/ncp_values.h"

typedef uint32_t sl_wisun_sa_family_t;

struct sl_wisun_sockaddr {
    sl_wisun_sa_family_t sa_family;
    uint8_t sa_data[];
};

struct sl_wisun_sockaddr_in6 {
    sl_wisun_sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t  sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t  sin6_scope_id;
};

sl_status_t sl_wisun_join(const uint8_t *name, sl_wisun_phy_config_t *phy_config)
{
    sl_wisun_msg_join_req_t req = {
        .header.id     = SL_WISUN_MSG_JOIN_REQ_ID,
        .header.length = htole16(sizeof(req)),
        .body.phy_config = *phy_config,
    };
    sl_wisun_msg_join_cnf_t cnf;

    if (strlen((const char *)name) >= SL_WISUN_NETWORK_NAME_SIZE)
        return SL_STATUS_INVALID_PARAMETER;
    strcpy((char *)req.body.name, (const char *)name);
    ncp_req(&req, NULL, &cnf, NULL);
    return cnf.body.status;
}

sl_status_t sl_wisun_set_trusted_certificate(uint16_t certificate_options,
                                             uint16_t certificate_length,
                                             const uint8_t *certificate)
{
    sl_wisun_msg_set_trusted_certificate_req_t req = {
        .header.id     = SL_WISUN_MSG_SET_TRUSTED_CERTIFICATE_REQ_ID,
        .header.length = htole16(sizeof(req) + certificate_length),
        .body.certificate_options = htole16(certificate_options),
        .body.certificate_length  = htole16(certificate_length),
    };
    sl_wisun_msg_set_trusted_certificate_cnf_t cnf;

    ncp_req(&req, certificate, &cnf, NULL);
    return cnf.body.status;
}

sl_status_t sl_wisun_set_device_certificate(uint16_t certificate_options,
                                            uint16_t certificate_length,
                                            const uint8_t *certificate)
{
    sl_wisun_msg_set_device_certificate_req_t req = {
        .header.id     = SL_WISUN_MSG_SET_DEVICE_CERTIFICATE_REQ_ID,
        .header.length = htole16(sizeof(req) + certificate_length),
        .body.certificate_options = htole16(certificate_options),
        .body.certificate_length  = htole16(certificate_length),
    };
    sl_wisun_msg_set_device_certificate_cnf_t cnf;

    ncp_req(&req, certificate, &cnf, NULL);
    return cnf.body.status;
}

sl_status_t sl_wisun_set_device_private_key(uint16_t key_options,
                                            uint16_t key_length,
                                            const uint8_t *key)
{
    sl_wisun_msg_set_device_private_key_req_t req = {
        .header.id     = SL_WISUN_MSG_SET_DEVICE_PRIVATE_KEY_REQ_ID,
        .header.length = htole16(sizeof(req) + key_length),
        .body.key_options = htole16(key_options),
        .body.key_length  = htole16(key_length),
    };
    sl_wisun_msg_set_device_private_key_cnf_t cnf;

    ncp_req(&req, key, &cnf, NULL);
    return cnf.body.status;
}

sl_status_t sl_wisun_get_ip_address(sl_wisun_ip_address_type_t address_type,
                                    in6_addr_t *address)
{
    sl_wisun_msg_get_ip_address_req_t req = {
        .header.id     = SL_WISUN_MSG_GET_IP_ADDRESS_REQ_ID,
        .header.length = htole16(sizeof(req)),
        .body.address_type = htole32(address_type),
    };
    sl_wisun_msg_get_ip_address_cnf_t cnf;

    ncp_req(&req, NULL, &cnf, NULL);
    return cnf.body.status;
}

int sl_wisun_socket_open(int domain, int type, int protocol)
{
    sl_wisun_msg_open_socket_req_t req = {
        .header.id     = SL_WISUN_MSG_OPEN_SOCKET_REQ_ID,
        .header.length = htole16(sizeof(req)),
        .body.domain   = htole32(domain),
        .body.type     = htole32(type),
        .body.protocol = htole32(protocol),
    };
    sl_wisun_msg_open_socket_cnf_t cnf;

    ncp_req(&req, NULL, &cnf, NULL);
    return cnf.body.socket_id;
}

int32_t sl_wisun_socket_sendto(int fd, const void *buf, uint32_t buf_len, int flags,
                               const struct sl_wisun_sockaddr *_dst, uint32_t dst_len)
{
    sl_wisun_msg_sendto_on_socket_req_t req = {
        .header.id     = SL_WISUN_MSG_SENDTO_ON_SOCKET_REQ_ID,
        .header.length = htole16(sizeof(req) + buf_len),
        .body.socket_id      = htole32(fd),
        .body.data_length    = htole16(buf_len),
    };
    sl_wisun_msg_sendto_on_socket_cnf_t cnf;
    const struct sl_wisun_sockaddr_in6 *dst;

    if (_dst->sa_family != SL_WISUN_AF_INET6 ||
        dst_len < sizeof(struct sl_wisun_sockaddr_in6))
        return SL_STATUS_INVALID_PARAMETER;
    dst = (const struct sl_wisun_sockaddr_in6 *)_dst;
    req.body.remote_address = dst->sin6_addr;
    req.body.remote_port    = dst->sin6_port;

    ncp_req(&req, buf, &cnf, NULL);
    return le32toh(cnf.body.data_length);
}
