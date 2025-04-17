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
#include <sl_wisun_msg_api.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <endian.h>
#include <errno.h>
#include <unistd.h>

#include "tools/simulation/ncp_values.h"

#include "ncp_socket.h"

void ncp_sk_open(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    static const struct ncp_val domains[] = {
        { 0, AF_INET6 },
    };
    static const struct ncp_val types[] = {
        { 1, SOCK_STREAM },
        { 2, SOCK_DGRAM },
        { 3, SOCK_RAW },
    };
    static const struct ncp_val protos[] = {
        { 0, IPPROTO_IPV6 },
        { 1, IPPROTO_ICMPV6 },
        { 2, IPPROTO_TCP },
        { 3, IPPROTO_UDP },
    };
    const sl_wisun_msg_open_socket_req_t *req = _req;
    sl_wisun_msg_open_socket_cnf_t *cnf = _cnf;
    int domain, type, proto;

    domain = ncp_ntoh(le32toh(req->body.domain),            domains, ARRAY_SIZE(domains));
    type   = ncp_ntoh(le32toh(req->body.type) & 0x0000ffff, types,   ARRAY_SIZE(types));
    proto  = ncp_ntoh(le32toh(req->body.protocol),          protos,  ARRAY_SIZE(protos));

    if (le32toh(req->body.type) & 0x00010000)
        type |= SOCK_NONBLOCK;

    cnf->body.socket_id = socket(domain, type, proto);
    cnf->body.status = htole32(cnf->body.socket_id < 0 ? ncp_status(errno) : SL_STATUS_OK);
}

void ncp_sk_close(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_close_socket_req_t *req = _req;
    sl_wisun_msg_close_socket_cnf_t *cnf = _cnf;
    int ret;

    ret = close(req->body.socket_id);
    cnf->body.status = htole32(ret < 0 ? ncp_status(errno) : SL_STATUS_OK);
}

void ncp_sk_bind(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_bind_socket_req_t *req = _req;
    sl_wisun_msg_bind_socket_cnf_t *cnf = _cnf;
    const struct sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        .sin6_addr   = req->body.local_address,
        .sin6_port   = req->body.local_port,
    };
    int ret;

    ret = bind(req->body.socket_id, (struct sockaddr *)&sin6, sizeof(sin6));
    cnf->body.status = htole32(ret < 0 ? ncp_status(errno) : SL_STATUS_OK);
}

void ncp_sk_send(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_send_on_socket_req_t *req = _req;
    sl_wisun_msg_send_on_socket_cnf_t *cnf = _cnf;
    ssize_t ret;

    ret = send(req->body.socket_id, req_data, req->body.data_length, 0);
    cnf->body.status = htole32(ret < 0 ? ncp_status(errno) : SL_STATUS_OK);
}
