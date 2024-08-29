/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https:www.silabs.com/about-us/legal/master-software-license-agreement
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include "app_wsbrd/net/netaddr_types.h"
#include "app_wsbrd/security/kmp/kmp_socket_if.h"
#include "app_wsbrd/ws/ws_eapol_relay.h"
#include "app_wsbrd/ws/ws_eapol_auth_relay.h"
#include "app_wsbrd/app/wsbrd.h"
#include "app_wsbrd/app/wsbr_mac.h"
#include "common/log.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/hif.h"
#include "interfaces.h"
#include "wsbrd_fuzz.h"

static struct fuzz_iface *fuzz_iface_new(struct fuzz_ctxt *ctxt)
{
    struct fuzz_iface *iface;
    int ret;

    ctxt->iface_count++;
    ctxt->iface_list = reallocarray(ctxt->iface_list, ctxt->iface_count, sizeof(struct fuzz_iface));
    FATAL_ON(!ctxt->iface_list, 2, "%s(): realloc: %m", __func__);
    iface = &ctxt->iface_list[ctxt->iface_count - 1];

    memset(iface, 0, sizeof(*iface));
    ret = pipe(iface->pipefd);
    FATAL_ON(ret < 0, 2, "pipe: %m");
    return iface;
}

static struct fuzz_iface *fuzz_iface_get(struct fuzz_ctxt *ctxt, int fd)
{
    for (int i = 0; i < ctxt->iface_count; i++)
        if (ctxt->iface_list[i].pipefd[0] == fd)
            return &ctxt->iface_list[i];
    BUG("fd=%i not registered", fd);
}

void fuzz_ind_replay_socket(struct rcp *rcp, struct iobuf_read *buf)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct fuzz_iface *iface;
    const uint8_t *data;
    uint8_t iface_index;
    size_t size;
    int ret;

    BUG_ON(rcp != &ctxt->wsbrd->rcp);
    if (!rcp->has_rf_list)
        FATAL(1, "interface command received during RCP init");
    FATAL_ON(!ctxt->replay_count, 1, "interface command received while replay is disabled");

    iface_index = hif_pop_u8(buf);
    BUG_ON(iface_index >= ctxt->iface_count, "iface_index=%u not registered", iface_index);
    iface = &ctxt->iface_list[iface_index];

    hif_pop_fixed_u8_array(buf, iface->src_addr.s6_addr, 16);
    hif_pop_fixed_u8_array(buf, iface->dst_addr.s6_addr, 16);
    iface->src_port = hif_pop_u16(buf);

    size = hif_pop_data_ptr(buf, &data);
    if (buf->err)
        return;

    ret = write(iface->pipefd[1], data, size);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < size, 2, "%s: write: Short write", __func__);
}

void __real_wsbr_tun_init(struct wsbr_ctxt *wsbrd);
void __wrap_wsbr_tun_init(struct wsbr_ctxt *wsbrd)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct fuzz_iface *iface;

    BUG_ON(ctxt->wsbrd != wsbrd);
    if (!ctxt->replay_count) {
        __real_wsbr_tun_init(wsbrd);
        return;
    }

    iface = fuzz_iface_new(ctxt);
    wsbrd->tun.fd = iface->pipefd[0];

    memcpy(ctxt->tun_gua, wsbrd->config.ipv6_prefix, 8);
    memcpy(ctxt->tun_gua + 8, &wsbrd->rcp.eui64, 8);
    ctxt->tun_gua[8] ^= 2;
    memcpy(ctxt->tun_lla, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(ctxt->tun_lla + 8, &wsbrd->rcp.eui64, 8);
    ctxt->tun_lla[8] ^= 2;
}

int __real_tun_addr_get_uc_global(const struct tun_ctx *tun, struct in6_addr *addr);
int __wrap_tun_addr_get_uc_global(const struct tun_ctx *tun, struct in6_addr *addr)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count) {
        memcpy(addr, ctxt->tun_gua, 16);
        return 0;
    } else {
        return __real_tun_addr_get_uc_global(tun, addr);
    }
}

int __real_tun_addr_get_linklocal(const struct tun_ctx *tun, struct in6_addr *addr);
int __wrap_tun_addr_get_linklocal(const struct tun_ctx *tun, struct in6_addr *addr)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count) {
        memcpy(addr, ctxt->tun_lla, 16);
        return 0;
    } else {
        return __real_tun_addr_get_linklocal(tun, addr);
    }
}

ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (!ctxt->replay_count)
        return __real_recv(sockfd, buf, len, flags);

    return read(sockfd, buf, len);
}

ssize_t __real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_sa, socklen_t *addrlen);
ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_sa, socklen_t *addrlen)
{
    struct sockaddr_in6 *src_ipv6 = (struct sockaddr_in6 *)src_sa;
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct fuzz_iface *iface;

    if (!ctxt->replay_count)
        return __real_recvfrom(sockfd, buf, len, flags, src_sa, addrlen);

    if (addrlen) {
        BUG_ON(*addrlen < sizeof(struct sockaddr_in6));
        *addrlen = sizeof(struct sockaddr_in6);
        iface = fuzz_iface_get(ctxt, sockfd);
        src_ipv6->sin6_family = AF_INET6;
        src_ipv6->sin6_port = htons(iface->src_port);
        src_ipv6->sin6_addr = iface->src_addr;
    }
    return read(sockfd, buf, len);
}

ssize_t __real_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    struct sockaddr_in6 *src_ipv6 = (struct sockaddr_in6 *)msg->msg_name;
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct in6_pktinfo pktinfo = { };
    struct fuzz_iface *iface;
    struct cmsghdr *cmsg;

    if (!ctxt->replay_count)
        return __real_recvmsg(sockfd, msg, flags);

    BUG_ON(msg->msg_iovlen != 1);
    iface = fuzz_iface_get(ctxt, sockfd);
    if (msg->msg_namelen) {
        BUG_ON(msg->msg_namelen < sizeof(struct sockaddr_in6));
        msg->msg_namelen = sizeof(struct sockaddr_in6);
        src_ipv6->sin6_family = AF_INET6;
        src_ipv6->sin6_port = htons(iface->src_port);
        src_ipv6->sin6_addr = iface->src_addr;
    }
    if (msg->msg_controllen) {
        BUG_ON(msg->msg_controllen < CMSG_SPACE(sizeof(struct in6_pktinfo)));
        cmsg = CMSG_FIRSTHDR(msg);
        BUG_ON(!cmsg);
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type  = IPV6_PKTINFO;
        pktinfo.ipi6_addr = iface->dst_addr;
        memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
    }
    return read(sockfd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
}

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct fuzz_iface *iface;

    if (!ctxt->replay_count)
        return __real_socket(domain, type, protocol);

    iface = fuzz_iface_new(ctxt);
    return iface->pipefd[0];
}

int __real_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (g_fuzz_ctxt.replay_count)
        return 0;
    else
        return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

int __real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (g_fuzz_ctxt.replay_count)
        return 0;
    else
        return __real_bind(sockfd, addr, addrlen);
}

ssize_t __real_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (g_fuzz_ctxt.replay_count)
        return len;
    else
        return __real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t __real_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t __wrap_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    ssize_t size = 0;

    if (g_fuzz_ctxt.replay_count) {
        for (int i = 0; i < msg->msg_iovlen; i++)
            size += msg->msg_iov[i].iov_len;
        return size;
    } else {
        return __real_sendmsg(sockfd, msg, flags);
    }
}
