/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common/bits.h"
#include "common/bus_uart.h"
#include "common/crc.h"
#include "common/endian.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/time_extra.h"

#include "capture.h"

struct capture_ctxt {
    int recfd;
    int *netfd_list;
    int netfd_cnt;
};

// The functions that this module wraps provide no way to retrieve this context
// from their arguments, so a global must be used.
struct capture_ctxt g_capture_ctxt = {
    .recfd = -1,
};

static void capture_record(struct capture_ctxt *ctxt, const void *buf, size_t buf_len)
{
    uint8_t hdr[4], fcs[2];
    const struct iovec iov[] = {
        { .iov_base = hdr,         .iov_len = sizeof(hdr) },
        { .iov_base = (void *)buf, .iov_len = buf_len     },
        { .iov_base = fcs,         .iov_len = sizeof(fcs) },
    };
    ssize_t ret;

    BUG_ON(buf_len > FIELD_MAX(UART_HDR_LEN_MASK));
    write_le16(hdr,     buf_len);
    write_le16(hdr + 2, crc16(CRC_INIT_HCS, hdr, 2));
    write_le16(fcs,     crc16(CRC_INIT_FCS, buf, buf_len));

    ret = writev(ctxt->recfd, iov, ARRAY_SIZE(iov));
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    if (ret != sizeof(hdr) + buf_len + sizeof(fcs))
        FATAL(2 ,"%s: write: Short write", __func__);
}

static void capture_record_timers(struct capture_ctxt *ctxt)
{
    struct iobuf_write iobuf = { };
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    FATAL_ON(ret < 0, 2, "clock_gettime: %m");

    hif_push_u8(&iobuf, HIF_CMD_IND_REPLAY_TIMER);
    hif_push_u64(&iobuf, time_now_ms(CLOCK_MONOTONIC));
    capture_record(ctxt, iobuf.data, iobuf.len);
    iobuf_free(&iobuf);
}

static void capture_record_netfd(struct capture_ctxt *ctxt, int iface_index,
                                 const struct in6_addr *src_addr, const struct in6_addr *dst_addr,
                                 uint16_t src_port, const void *buf, size_t buf_len)
{
    struct iobuf_write iobuf = { };

    hif_push_u8(&iobuf, HIF_CMD_IND_REPLAY_SOCKET);
    hif_push_u8(&iobuf, iface_index);
    hif_push_fixed_u8_array(&iobuf, src_addr->s6_addr, 16);
    hif_push_fixed_u8_array(&iobuf, dst_addr->s6_addr, 16);
    hif_push_u16(&iobuf, src_port);
    hif_push_data(&iobuf, buf, buf_len);
    capture_record(ctxt, iobuf.data, iobuf.len);
    iobuf_free(&iobuf);
}

static bool capture_try_netfd(struct capture_ctxt *ctxt, int fd,
                              const struct in6_addr *src_addr,
                              const struct in6_addr *dst_addr,
                              uint16_t src_port,
                              const void *buf, size_t buf_len)
{
    for (int i = 0; i < ctxt->netfd_cnt; i++) {
        if (ctxt->netfd_list[i] == fd) {
            capture_record_timers(ctxt);
            capture_record_netfd(ctxt, i, src_addr, dst_addr, 0, buf, buf_len);
            return true;
        }
    }
    return false;
}

ssize_t xread(int fd, void *buf, size_t buf_len)
{
    struct capture_ctxt *ctxt = &g_capture_ctxt;
    ssize_t out_len;

    out_len = read(fd, buf, buf_len);
    if (out_len < 0 || ctxt->recfd < 0)
        return out_len;

    capture_try_netfd(ctxt, fd, &in6addr_any, &in6addr_any, 0, buf, out_len);
    return out_len;
}

ssize_t xrecv(int fd, void *buf, size_t buf_len, int flags)
{
    struct capture_ctxt *ctxt = &g_capture_ctxt;
    ssize_t out_len;

    out_len = recv(fd, buf, buf_len, flags);
    if (out_len < 0 || ctxt->recfd < 0)
        return out_len;

    capture_try_netfd(ctxt, fd, &in6addr_any, &in6addr_any, 0, buf, out_len);
    return out_len;
}

ssize_t xrecvfrom(int fd, void *buf, size_t buf_len, int flags, struct sockaddr *src, socklen_t *src_len)
{
    const struct in6_addr *src_addr = &in6addr_any;
    struct capture_ctxt *ctxt = &g_capture_ctxt;
    const struct sockaddr_in6 *src_in6;
    uint16_t src_port = 0;
    ssize_t out_len;

    out_len = recvfrom(fd, buf, buf_len, flags, src, src_len);
    if (out_len < 0 || ctxt->recfd < 0)
        return out_len;

    if (src_len) {
        src_in6 = (struct sockaddr_in6 *)src;
        BUG_ON(*src_len < sizeof(struct sockaddr_in6));
        BUG_ON(src_in6->sin6_family != AF_INET6);
        src_addr = &src_in6->sin6_addr;
        src_port = ntohs(src_in6->sin6_port);
    }
    capture_try_netfd(ctxt, fd, src_addr, &in6addr_any, src_port, buf, out_len);
    return out_len;
}

ssize_t xrecvmsg(int fd, struct msghdr *msg, int flags)
{
    const struct in6_addr *src_addr = &in6addr_any;
    const struct in6_addr *dst_addr = &in6addr_any;
    struct capture_ctxt *ctxt = &g_capture_ctxt;
    const struct sockaddr_in6 *src_in6;
    const struct in6_pktinfo *pktinfo;
    uint16_t src_port = 0;
    struct cmsghdr *cmsg;
    ssize_t out_len;

    out_len = recvmsg(fd, msg, flags);
    if (out_len < 0 || ctxt->recfd < 0)
        return out_len;

    BUG_ON(!msg || msg->msg_iovlen != 1);
    if (msg->msg_name) {
        src_in6 = (struct sockaddr_in6 *)msg->msg_name;
        BUG_ON(msg->msg_namelen < sizeof(struct sockaddr_in6));
        BUG_ON(src_in6->sin6_family != AF_INET6);
        src_addr = &src_in6->sin6_addr;
        src_port = ntohs(src_in6->sin6_port);
    }
    if (msg->msg_controllen) {
        cmsg = CMSG_FIRSTHDR(msg);
        BUG_ON(!cmsg);
        BUG_ON(cmsg->cmsg_level != IPPROTO_IPV6);
        BUG_ON(cmsg->cmsg_type != IPV6_PKTINFO);
        BUG_ON(cmsg->cmsg_len < sizeof(struct in6_pktinfo));
        pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
        dst_addr = &pktinfo->ipi6_addr;
    }
    capture_try_netfd(ctxt, fd, src_addr, dst_addr, src_port,
                      msg->msg_iov[0].iov_base, out_len);
    return out_len;
}

// write() variants are provided for consistency, but are not needed for capture.

ssize_t xwrite(int fd, const void *buf, size_t buf_len)
{
    return write(fd, buf, buf_len);
}

ssize_t xsend(int fd, const void *buf, size_t buf_len, int flags)
{
    return send(fd, buf, buf_len, flags);
}

ssize_t xsendto(int fd, const void *buf, size_t buf_len, int flags,
                const struct sockaddr *dst, socklen_t dst_len)
{
    return sendto(fd, buf, buf_len, flags, dst, dst_len);
}

ssize_t xsendmsg(int fd, const struct msghdr *msg, int flags)
{
    return sendmsg(fd, msg, flags);
}

ssize_t xgetrandom(void *buf, size_t buf_len, unsigned int flags)
{
    static bool init = false;
    struct capture_ctxt *ctxt = &g_capture_ctxt;
    uint8_t *ptr = (uint8_t *)buf;
    size_t cnt = buf_len;

    if (ctxt->recfd < 0)
        return getrandom(buf, buf_len, flags);

    if (!init) {
        srand(0);
        init = true;
    }
    while (cnt--)
        *ptr++ = rand();
    return buf_len;
}

// MbedTLS uses time as source of entropy. The time function can be overwritten
// using mbedtls_platform_set_time(), but this requires the compilation flag
// MBEDTLS_PLATFORM_TIME_ALT which is not part of the default MbedTLS
// configuration. time() is only used by MbedTLS thankfully, so it can be
// wrapped to return a constant value.
time_t __real_time(time_t *res);
time_t __wrap_time(time_t *res)
{
    static const time_t val = 1750000000; // 2025-06-15 15:06:40
    struct capture_ctxt *ctxt = &g_capture_ctxt;

    if (ctxt->recfd < 0)
        return __real_time(res);

    if (res)
        *res = val;
    return val;
}

void capture_record_hif(const void *buf, size_t buf_len)
{
    struct capture_ctxt *ctxt = &g_capture_ctxt;

    if (ctxt->recfd < 0)
        return;
    capture_record_timers(ctxt);
    capture_record(ctxt, buf, buf_len);
}

void capture_register_netfd(int fd)
{
    struct capture_ctxt *ctxt = &g_capture_ctxt;

    ctxt->netfd_cnt++;
    ctxt->netfd_list = realloc(ctxt->netfd_list, sizeof(int) * ctxt->netfd_cnt);
    FATAL_ON(!ctxt->netfd_list, 2, "%s: realloc(): %m", __func__);
    ctxt->netfd_list[ctxt->netfd_cnt - 1] = fd;
}

void capture_start(const char *filename)
{
    struct capture_ctxt *ctxt = &g_capture_ctxt;

    ctxt->recfd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (ctxt->recfd < 0)
        FATAL(2, "open %s: %m", filename);
}
