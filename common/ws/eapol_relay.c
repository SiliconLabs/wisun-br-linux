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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include "common/ws/ws_interface.h"
#include "common/ieee802154_frame.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"

#include "eapol_relay.h"

int eapol_relay_start(const char ifname[IF_NAMESIZE])
{
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_addr   = IN6ADDR_ANY_INIT,
        .sin6_port   = htons(EAPOL_RELAY_PORT),
    };
    int ret, fd;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(fd < 0, 2, "%s: socket: %m", __func__);

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    FATAL_ON(ret < 0, 2, "%s: bind: %m", __func__);

    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IF_NAMESIZE);
    FATAL_ON(ret < 0, 2, "%s: setsockopt SO_BINDTODEVICE: %m", __func__);

    return fd;
}

ssize_t eapol_relay_recv(int fd, void *buf, size_t buf_len, struct in6_addr *src,
                         struct eui64 *supp_eui64, uint8_t *kmp_id)
{
    struct iovec iov[3] = {
        // Wi-SUN FAN 1.1v08 Figure 6-1 EAPOL Relay Datagram
        { .iov_base = supp_eui64, .iov_len = sizeof(*supp_eui64) },
        { .iov_base = kmp_id,     .iov_len = sizeof(*kmp_id) },
        { .iov_base = buf,        .iov_len = buf_len },
    };
    struct sockaddr_in6 sin6;
    struct msghdr msg = {
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
        .msg_name    = &sin6,
        .msg_namelen = sizeof(sin6),
    };
    ssize_t ret;

    ret = recvmsg(fd, &msg, 0);
    if (ret < 0) {
        WARN("%s: recv: %m", __func__);
        return -errno;
    }
    if (ret < sizeof(*supp_eui64) + sizeof(*kmp_id)) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "eapol-rel");
        return -EINVAL;
    }
    ret -= sizeof(*supp_eui64) + sizeof(*kmp_id);
    if (src)
        *src = sin6.sin6_addr;
    TRACE(TR_SECURITY, "sec: %-8s supp=%s", "rx-eapol-rel", tr_eui64(supp_eui64->u8));
    return ret;
}

void eapol_relay_send(int fd, const void *buf, size_t buf_len,
                      const struct in6_addr *dst,
                      const struct eui64 *supp_eui64, uint8_t kmp_id)
{
    struct iovec iov[] = {
        // Wi-SUN FAN 1.1v08 Figure 6-1 EAPOL Relay Datagram
        { .iov_base = (void *)supp_eui64, .iov_len = sizeof(*supp_eui64) },
        { .iov_base = &kmp_id,            .iov_len = sizeof(kmp_id)      },
        { .iov_base = (void*)buf,         .iov_len = buf_len             },
    };
    struct sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(EAPOL_RELAY_PORT),
        .sin6_addr   = *dst,
    };
    struct msghdr msg = {
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
        .msg_name    = &sin6,
        .msg_namelen = sizeof(sin6),
    };
    ssize_t ret;

    TRACE(TR_SECURITY, "sec: %-8s supp=%s", "tx-eapol-rel", tr_eui64(supp_eui64->u8));
    ret = sendmsg(fd, &msg, 0);
    if (ret < 0)
        TRACE(TR_TX_ABORT, "tx-abort %-9s: %m", "eapol-rel");
}
