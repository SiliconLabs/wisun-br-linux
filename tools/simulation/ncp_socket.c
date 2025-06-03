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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <endian.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "tools/simulation/ncp_ind.h"
#include "tools/simulation/ncp_values.h"
#include "common/log.h"

#include "ncp_socket.h"

// Thread used to simulate an application doing socket reads.
pthread_t g_sk_thread;
int g_sk_epfd = -1;

static void *ncp_sk_thread(void *arg)
{
    struct sockaddr_in6 sin6;
    struct epoll_event event;
    uint8_t buf[1500];
    int ret;

    g_sk_epfd = epoll_create1(0);
    FATAL_ON(g_sk_epfd < 0, 2, "epoll_create: %m");

    while (1) {
        ret = epoll_wait(g_sk_epfd, &event, 1, -1);
        if (ret < 0 && errno == EINTR)
            continue;
        FATAL_ON(ret < 0, 2, "epoll_wait: %m");

        ret = recvfrom(event.data.fd, buf, sizeof(buf), 0,
                       (struct sockaddr *)&sin6, (socklen_t[]){ sizeof(sin6) });
        FATAL_ON(ret < 0, 2, "recvfrom: %m");
        ncp_send_sk_data(event.data.fd, buf, ret, &sin6);
    }
}

__attribute__((constructor))
static void ncp_sk_init(void)
{
    int ret;

    ret = pthread_create(&g_sk_thread, NULL, ncp_sk_thread, NULL);
    FATAL_ON(ret, 2, "pthread_create: %s", strerror(ret));
}

__attribute__((destructor))
static void ncp_sk_exit(void)
{
    pthread_cancel(g_sk_thread);
    pthread_join(g_sk_thread, NULL);
}

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

static void ncp_sk_setopt_evtmode(const sl_wisun_msg_set_socket_option_req_t *req,
                                  const uint32_t *mode,
                                  sl_wisun_msg_set_socket_option_cnf_t *cnf)
{
    struct epoll_event event = { };
    int ret;

    if (req->body.option_length != sizeof(*mode)) {
        cnf->body.status = SL_STATUS_INVALID_PARAMETER;
        return;
    }

    ret = epoll_ctl(g_sk_epfd, EPOLL_CTL_DEL, req->body.socket_id, NULL);
    if (ret < 0 && errno != ENOENT)
        FATAL(2, "epoll_ctl DEL %i: %m", req->body.socket_id);

    switch (*mode) {
    case 0: // SL_WISUN_SOCKET_EVENT_MODE_INDICATION
        event.events = EPOLLIN;
        event.data.fd = req->body.socket_id;
        ret = epoll_ctl(g_sk_epfd, EPOLL_CTL_ADD, req->body.socket_id, &event);
        FATAL_ON(ret < 0, 2, "epoll_ctl ADD %i: %m", req->body.socket_id);
        break;
    case 1: // SL_WISUN_SOCKET_EVENT_MODE_POLLING
    default:
        cnf->body.status = SL_STATUS_NOT_SUPPORTED;
        break;
    }
}

void ncp_sk_setopt(const void *_req, const void *req_data, void *_cnf, void *cnf_data)
{
    const sl_wisun_msg_set_socket_option_req_t *req = _req;
    sl_wisun_msg_set_socket_option_cnf_t *cnf = _cnf;
    int ret, level, optname;

    level = optname = -1;
    switch (req->body.level) {
    case 1: // SOL_APPLICATION
        switch (req->body.option_name) {
        case 10: // SO_EVENT_MODE
            ncp_sk_setopt_evtmode(req, req_data, cnf);
            return;
        }
        break;
    }

    if (level < 0 || optname < 0) {
        cnf->body.status = SL_STATUS_NOT_SUPPORTED;
    } else {
        ret = setsockopt(req->body.socket_id, level, optname, req_data, req->body.option_length);
        cnf->body.status = ret < 0 ? ncp_status(errno) : SL_STATUS_OK;
    }
}
