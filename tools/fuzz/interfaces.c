/*
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
#include "6lbr/core/netaddr_types.h"
#include "6lbr/security/kmp/kmp_socket_if.h"
#include "6lbr/6lowpan/ws/ws_bbr_api.h"
#include "6lbr/6lowpan/ws/ws_eapol_relay.h"
#include "6lbr/6lowpan/ws/ws_eapol_auth_relay.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "common/log.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/hif.h"
#include "interfaces.h"
#include "wsbrd_fuzz.h"
#include "capture.h"

static int fuzz_dhcp_get_socket_id()
{
    return g_ctxt.dhcp_server.fd;
}

static int fuzz_rpl_get_socket_fd()
{
    return g_ctxt.rpl_root.sockfd;
}

static struct {
    int interface;
    int (*get_capture_fd)();
    int replay_write_fd;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
} s_sockets[] = {
    { IF_DHCP_SERVER,    fuzz_dhcp_get_socket_id,               -1 },
    { IF_EAPOL_RELAY,    ws_eapol_auth_relay_get_socket_fd,     -1 },
    { IF_BR_EAPOL_RELAY, ws_eapol_relay_get_socket_fd,          -1 },
    { IF_PAE_AUTH,       kmp_socket_if_get_pae_socket_fd,       -1 },
    { IF_RADIUS,         kmp_socket_if_get_radius_sockfd,       -1 },
    { IF_RPL,            fuzz_rpl_get_socket_fd,                -1 },
};
static_assert(ARRAY_SIZE(s_sockets) == IF_SOCKET_COUNT, "missing socket entries for capture/replay");


void fuzz_ind_replay_socket(struct rcp *rcp, struct iobuf_read *buf)
{
    static bool init = false;
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    const uint8_t *data;
    uint16_t src_port;
    uint8_t interface;
    size_t size;
    int ret, i;
    int fd = -1;

    BUG_ON(rcp != &ctxt->wsbrd->rcp);
    FATAL_ON(!fuzz_is_main_loop(ctxt->wsbrd), 1, "interface command received during RCP init");
    FATAL_ON(!ctxt->replay_count, 1, "interface command received while replay is disabled");

    if (!init) {
        fuzz_replay_socket_init(ctxt);
        init = true;
    }

    interface = hif_pop_u8(buf);
    hif_pop_fixed_u8_array(buf, src_addr, 16);
    hif_pop_fixed_u8_array(buf, dst_addr, 16);
    src_port = hif_pop_u16(buf);

    if (interface == IF_TUN) {
        fd = ctxt->tun_pipe[1];
    } else {
        for (i = 0; i < ARRAY_SIZE(s_sockets); i++) {
            if (interface == s_sockets[i].interface) {
                fd = s_sockets[i].replay_write_fd;
                memcpy(s_sockets[i].src_addr, src_addr, 16);
                memcpy(s_sockets[i].dst_addr, dst_addr, 16);
                s_sockets[i].src_port = src_port;
                break;
            }
        }
    }
    if (fd < 0) {
        WARN("%d: no such interface", interface);
        return;
    }

    size = hif_pop_data_ptr(buf, &data);
    if (buf->err)
        return;

    ret = write(fd, data, size);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < size, 2, "%s: write: Short write", __func__);
}

void __real_wsbr_tun_init(struct wsbr_ctxt *wsbrd);
void __wrap_wsbr_tun_init(struct wsbr_ctxt *wsbrd)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    int ret;

    BUG_ON(ctxt->wsbrd != wsbrd);
    if (!ctxt->replay_count) {
        __real_wsbr_tun_init(wsbrd);
        return;
    }

    ret = pipe(ctxt->tun_pipe);
    FATAL_ON(ret < 0, 2, "pipe: %m");
    wsbrd->tun_fd = ctxt->tun_pipe[0];

    memcpy(ctxt->tun_gua, wsbrd->config.ipv6_prefix, 8);
    memcpy(ctxt->tun_gua + 8, wsbrd->rcp.eui64, 8);
    ctxt->tun_gua[8] ^= 2;
    memcpy(ctxt->tun_lla, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(ctxt->tun_lla + 8, wsbrd->rcp.eui64, 8);
    ctxt->tun_lla[8] ^= 2;
}

int __real_tun_addr_get_global_unicast(char* if_name, uint8_t ip[16]);
int __wrap_tun_addr_get_global_unicast(char* if_name, uint8_t ip[16])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count) {
        memcpy(ip, ctxt->tun_gua, 16);
        return 0;
    } else {
        return __real_tun_addr_get_global_unicast(if_name, ip);
    }
}

int __real_tun_addr_get_link_local(char* if_name, uint8_t ip[16]);
int __wrap_tun_addr_get_link_local(char* if_name, uint8_t ip[16])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count) {
        memcpy(ip, ctxt->tun_lla, 16);
        return 0;
    } else {
        return __real_tun_addr_get_link_local(if_name, ip);
    }
}

static int fuzz_find_socket_index(int fd)
{
    for (int i = 0; i < ARRAY_SIZE(s_sockets); i++)
        if (fd == s_sockets[i].get_capture_fd())
            return i;
    BUG("invalid socket");
}

void fuzz_replay_socket_init(struct fuzz_ctxt *ctxt)
{
    int j;

    for (int i = 0; i < IF_SOCKET_COUNT; i++) {
        for (j = 0; j < IF_SOCKET_COUNT; j++) {
            if (ctxt->socket_pipes[i][0] == s_sockets[j].get_capture_fd()) {
                s_sockets[j].replay_write_fd = ctxt->socket_pipes[i][1];
                break;
            }
        }
        BUG_ON(j == IF_SOCKET_COUNT, "unassigned replay pipe");
    }
}

static void fuzz_capture_socket(int fd,
                                const uint8_t src_addr[16],
                                const uint8_t dst_addr[16],
                                uint16_t src_port,
                                const void *buf, size_t size)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    int i;

    if (size <= 0)
        return;

    fuzz_capture_timers(ctxt);
    i = fuzz_find_socket_index(fd);
    fuzz_capture_interface(ctxt, s_sockets[i].interface,
                           src_addr, dst_addr, src_port,
                           buf, size);
}

ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    ssize_t size;

    if (ctxt->replay_count)
        return read(sockfd, buf, len);

    size = __real_recv(sockfd, buf, len, flags);
    if (ctxt->capture_fd >= 0)
        fuzz_capture_socket(sockfd, in6addr_any.s6_addr, in6addr_any.s6_addr, 0, buf, size);

    return size;
}

ssize_t __real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_sa, socklen_t *addrlen);
ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_sa, socklen_t *addrlen)
{
    struct sockaddr_in6 *src_ipv6 = (struct sockaddr_in6 *)src_sa;
    const uint8_t *src_addr = in6addr_any.s6_addr;
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    uint16_t src_port = 0;
    ssize_t size;
    int i;

    if (ctxt->replay_count) {
        if (src_addr) {
            BUG_ON(*addrlen < sizeof(struct sockaddr_in6));
            *addrlen = sizeof(struct sockaddr_in6);
            i = fuzz_find_socket_index(sockfd);
            src_ipv6->sin6_family = AF_INET6;
            src_ipv6->sin6_port = htons(s_sockets[i].src_port);
            memcpy(src_ipv6->sin6_addr.s6_addr, s_sockets[i].src_addr, 16);
        }
        return read(sockfd, buf, len);
    }

    size = __real_recvfrom(sockfd, buf, len, flags, src_sa, addrlen);
    if (ctxt->capture_fd >= 0) {
        if (src_sa) {
            BUG_ON(src_ipv6->sin6_family != AF_INET6);
            src_addr = src_ipv6->sin6_addr.s6_addr;
            src_port = ntohs(src_ipv6->sin6_port);
        }
        fuzz_capture_socket(sockfd, src_addr, in6addr_any.s6_addr, src_port, buf, size);
    }

    return size;
}

ssize_t __real_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    struct sockaddr_in6 *src_ipv6 = (struct sockaddr_in6 *)msg->msg_name;
    const uint8_t *src_addr = in6addr_any.s6_addr;
    const uint8_t *dst_addr = in6addr_any.s6_addr;
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct in6_pktinfo pktinfo = { };
    uint16_t src_port = 0;
    struct cmsghdr *cmsg;
    ssize_t size;
    int i;

    BUG_ON(msg->msg_iovlen != 1);
    if (ctxt->replay_count) {
        i = fuzz_find_socket_index(sockfd);
        if (msg->msg_namelen) {
            BUG_ON(msg->msg_namelen < sizeof(struct sockaddr_in6));
            msg->msg_namelen = sizeof(struct sockaddr_in6);
            src_ipv6->sin6_family = AF_INET6;
            src_ipv6->sin6_port = htons(s_sockets[i].src_port);
            memcpy(src_ipv6->sin6_addr.s6_addr, s_sockets[i].src_addr, 16);
        }
        if (msg->msg_controllen) {
            BUG_ON(msg->msg_controllen < CMSG_SPACE(sizeof(struct in6_pktinfo)));
            cmsg = CMSG_FIRSTHDR(msg);
            BUG_ON(!cmsg);
            cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type  = IPV6_PKTINFO;
            memcpy(pktinfo.ipi6_addr.s6_addr, s_sockets[i].dst_addr, 16);
            memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
        }
        return read(sockfd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
    }

    size = __real_recvmsg(sockfd, msg, flags);
    if (ctxt->capture_fd >= 0) {
        if (msg->msg_namelen) {
            BUG_ON(src_ipv6->sin6_family != AF_INET6);
            src_addr = src_ipv6->sin6_addr.s6_addr;
            src_port = ntohs(src_ipv6->sin6_port);
        }
        if (msg->msg_controllen) {
            cmsg = CMSG_FIRSTHDR(msg);
            BUG_ON(!cmsg);
            BUG_ON(cmsg->cmsg_level != IPPROTO_IPV6);
            BUG_ON(cmsg->cmsg_type != IPV6_PKTINFO);
            BUG_ON(cmsg->cmsg_len < sizeof(struct in6_pktinfo));
            dst_addr = ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr.s6_addr;
        }
        fuzz_capture_socket(sockfd, src_addr, dst_addr, src_port,
                            msg->msg_iov[0].iov_base, size);

    }

    return size;
}

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    int ret;

    if (!ctxt->replay_count)
        return __real_socket(domain, type, protocol);

    BUG_ON(ctxt->socket_pipe_count >= IF_SOCKET_COUNT);
    ret = pipe(ctxt->socket_pipes[ctxt->socket_pipe_count]);
    FATAL_ON(ret < 0, 2, "pipe: %m");

    return ctxt->socket_pipes[ctxt->socket_pipe_count++][0];
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
