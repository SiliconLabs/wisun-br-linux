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
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include "stack/source/core/ns_address_internal.h"
#include "stack/source/security/kmp/kmp_socket_if.h"
#include "stack/ws_bbr_api.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "common/log.h"
#include "common/iobuf.h"
#include "common/utils.h"
#include "common/spinel_buffer.h"
#include "interfaces.h"
#include "wsbrd_fuzz.h"
#include "capture.h"

static int fuzz_dhcp_get_socket_id()
{
    return g_ctxt.dhcp_server.fd;
}

static struct {
    int interface;
    int (*get_capture_fd)();
    int replay_write_fd;
    uint8_t src_addr[16];
    uint16_t src_port;
} s_sockets[] = {
    { IF_DHCP_SERVER,    fuzz_dhcp_get_socket_id,               -1 },
    { IF_EAPOL_RELAY,    ws_bbr_eapol_auth_relay_get_socket_fd, -1 },
    { IF_BR_EAPOL_RELAY, ws_bbr_eapol_relay_get_socket_fd,      -1 },
    { IF_PAE_AUTH,       kmp_socket_if_get_pae_socket_fd,       -1 },
};
static_assert(ARRAY_SIZE(s_sockets) == IF_SOCKET_COUNT, "missing socket entries for capture/replay");

void fuzz_spinel_replay_interface(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    static bool init = false;
    uint8_t src_addr[16];
    const uint8_t *data;
    uint16_t src_port;
    uint8_t interface;
    size_t size;
    int ret, i;
    int fd = -1;

    FATAL_ON(!fuzz_is_main_loop(&g_ctxt), 1, "interface command received during RCP init");
    FATAL_ON(!g_fuzz_ctxt.replay_count, 1, "interface command received while replay is disabled");

    if (!init) {
        fuzz_replay_socket_init(&g_fuzz_ctxt);
        init = true;
    }

    interface = spinel_pop_u8(buf);
    spinel_pop_fixed_u8_array(buf, src_addr, 16);
    src_port = spinel_pop_u16(buf);

    if (interface == IF_TUN) {
        fd = g_fuzz_ctxt.tun_pipe[1];
    } else {
        for (i = 0; i < ARRAY_SIZE(s_sockets); i++) {
            if (interface == s_sockets[i].interface) {
                fd = s_sockets[i].replay_write_fd;
                memcpy(s_sockets[i].src_addr, src_addr, 16);
                s_sockets[i].src_port = src_port;
                break;
            }
        }
    }
    if (fd < 0) {
        WARN("%d: no such interface", interface);
        return;
    }

    size = spinel_pop_data_ptr(buf, &data);
    if (buf->err)
        return;

    ret = write(fd, data, size);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < size, 2, "%s: write: Short write", __func__);
}

void __real_wsbr_tun_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    int ret;

    if (!g_fuzz_ctxt.replay_count) {
        __real_wsbr_tun_init(ctxt);
        return;
    }

    ret = pipe(g_fuzz_ctxt.tun_pipe);
    FATAL_ON(ret < 0, 2, "pipe: %m");
    ctxt->tun_fd = g_fuzz_ctxt.tun_pipe[0];

    memcpy(g_fuzz_ctxt.tun_gua, g_ctxt.config.ipv6_prefix, 8);
    memcpy(g_fuzz_ctxt.tun_gua + 8, g_ctxt.rcp.eui64, 8);
    g_fuzz_ctxt.tun_gua[8] ^= 2;
    memcpy(g_fuzz_ctxt.tun_lla, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(g_fuzz_ctxt.tun_lla + 8, g_ctxt.rcp.eui64, 8);
    g_fuzz_ctxt.tun_lla[8] ^= 2;
}

int __real_tun_addr_get_global_unicast(char* if_name, uint8_t ip[static 16]);
int __wrap_tun_addr_get_global_unicast(char* if_name, uint8_t ip[static 16])
{
    if (g_fuzz_ctxt.replay_count) {
        memcpy(ip, g_fuzz_ctxt.tun_gua, 16);
        return 0;
    } else {
        return __real_tun_addr_get_global_unicast(if_name, ip);
    }
}

int __real_tun_addr_get_link_local(char* if_name, uint8_t ip[static 16]);
int __wrap_tun_addr_get_link_local(char* if_name, uint8_t ip[static 16])
{
    if (g_fuzz_ctxt.replay_count) {
        memcpy(ip, g_fuzz_ctxt.tun_lla, 16);
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
        BUG_ON(ctxt->socket_pipes[i][0] < 0, "uninitialized replay pipe");
        for (j = 0; j < IF_SOCKET_COUNT; j++) {
            if (ctxt->socket_pipes[i][0] == s_sockets[j].get_capture_fd()) {
                s_sockets[j].replay_write_fd = ctxt->socket_pipes[i][1];
                break;
            }
        }
        BUG_ON(j == IF_SOCKET_COUNT, "unassigned replay pipe");
    }
}

static void fuzz_capture_socket(int fd, const uint8_t src_addr[16], uint16_t src_port, const void *buf, size_t size)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    int i;

    if (size <= 0)
        return;

    fuzz_capture_timers(ctxt);
    i = fuzz_find_socket_index(fd);
    fuzz_capture_interface(ctxt, s_sockets[i].interface, src_addr, src_port, buf, size);
}

ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t size;

    if (g_fuzz_ctxt.replay_count)
        return read(sockfd, buf, len);

    size = __real_recv(sockfd, buf, len, flags);
    if (g_fuzz_ctxt.capture_fd >= 0)
        fuzz_capture_socket(sockfd, ADDR_UNSPECIFIED, 0, buf, size);

    return size;
}

ssize_t __real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct sockaddr_in6 *src_ipv6 = (struct sockaddr_in6 *)src_addr;
    ssize_t size;
    int i;

    if (g_fuzz_ctxt.replay_count) {
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

    size = __real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (g_fuzz_ctxt.capture_fd >= 0) {
        if (src_addr) {
            BUG_ON(src_addr->sa_family != AF_INET6);
            fuzz_capture_socket(sockfd,
                                src_ipv6->sin6_addr.s6_addr, ntohs(src_ipv6->sin6_port),
                                buf, size);
        } else {
            fuzz_capture_socket(sockfd, ADDR_UNSPECIFIED, 0, buf, size);
        }
    }

    return size;
}

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
    int ret;

    if (!g_fuzz_ctxt.replay_count)
        return __real_socket(domain, type, protocol);

    BUG_ON(g_fuzz_ctxt.socket_pipe_count >= IF_SOCKET_COUNT);
    ret = pipe(g_fuzz_ctxt.socket_pipes[g_fuzz_ctxt.socket_pipe_count]);
    FATAL_ON(ret < 0, 2, "pipe: %m");

    return g_fuzz_ctxt.socket_pipes[g_fuzz_ctxt.socket_pipe_count++][0];
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
