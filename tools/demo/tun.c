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
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>

#include "common/ipv6_cksum.h"
#include "common/log.h"
#include "common/tun.h"

enum {
    PFD_TUN,
    PFD_SOCKET,
    PFD_COUNT,
};

static size_t pkt_build_icmp(uint8_t buf[1500], const struct in6_addr *src, const struct in6_addr *dst)
{
    const char payload[] = "Hello, world";
    struct icmp6_hdr *icmp6;
    struct ip6_hdr *ip6;

    ip6 = (struct ip6_hdr *)buf;
    ip6->ip6_vfc  = 6 << 4;
    ip6->ip6_plen = htons(sizeof(*icmp6) + sizeof(payload));
    ip6->ip6_nxt  = IPPROTO_ICMPV6;
    ip6->ip6_hlim = 255;
    ip6->ip6_src  = *src;
    ip6->ip6_dst  = *dst;

    icmp6 = (struct icmp6_hdr *)(ip6 + 1);
    icmp6->icmp6_type  = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code  = 0;
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_id    = htons(0);
    icmp6->icmp6_seq   = htons(0);
    icmp6->icmp6_cksum = ipv6_cksum(src, dst, ip6->ip6_nxt, icmp6, ntohs(ip6->ip6_plen));

    return sizeof(*ip6) + ntohs(ip6->ip6_plen);
}

static size_t pkt_build_udp(uint8_t buf[1500], const struct in6_addr *src, const struct in6_addr *dst)
{
    const char payload[] = "Hello, world";
    struct ip6_hdr *ip6;
    struct udphdr *udp;

    ip6 = (struct ip6_hdr *)buf;
    ip6->ip6_vfc  = 6 << 4;
    ip6->ip6_plen = htons(sizeof(*udp) + sizeof(payload));
    ip6->ip6_nxt  = IPPROTO_UDP;
    ip6->ip6_hlim = 255;
    ip6->ip6_src  = *src;
    ip6->ip6_dst  = *dst;

    udp = (struct udphdr *)(ip6 + 1);
    udp->uh_sport = htons(IPPORT_ECHO);
    udp->uh_dport = htons(IPPORT_ECHO);
    udp->uh_ulen  = ip6->ip6_plen;
    udp->uh_sum   = 0;

    memcpy(udp + 1, payload, sizeof(payload));

    udp->uh_sum = ipv6_cksum(src, dst, ip6->ip6_nxt, udp, ntohs(ip6->ip6_plen));

    return sizeof(*ip6) + ntohs(ip6->ip6_plen);
}

static void hexdump(const uint8_t *buf, size_t buf_len)
{
    for (size_t offset = 0; offset < buf_len; offset += 16) {
        printf("%08zx:", offset);
        for (unsigned int i = 0; i < 16 && offset + i < buf_len; i++)
            printf(" %02x", *buf++);
        printf("\n");
    }
}

static void tun_recv(struct tun_ctx *tun)
{
    uint8_t buf[1500];
    ssize_t size;

    size = read(tun->fd, buf, sizeof(buf));
    FATAL_ON(size < 0, 2, "%s: read: %m", __func__);
    INFO("rx-tun: %zi bytes", size);
    hexdump(buf, size);
}

static void sock_recv(int fd)
{
    struct sockaddr_in6 sockaddr;
    char ifname[IF_NAMESIZE];
    socklen_t sockaddr_len;
    uint8_t buf[1500];
    ssize_t size;

    sockaddr_len = sizeof(sockaddr);
    size = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sockaddr, &sockaddr_len);
    FATAL_ON(size < 0, 2, "%s: recvfrom: %m", __func__);
    INFO("rx-udp: %zi bytes", size);
    hexdump(buf, size);

    if (sockaddr_len < sizeof(sockaddr) || sockaddr.sin6_family != AF_INET6) {
        WARN("%s: unsupported address", __func__);
        return;
    }

    size = sendto(fd, buf, size, 0, (struct sockaddr *)&sockaddr, sockaddr_len);
    FATAL_ON(size < 0, 2, "%s: sendto %s%%%s: %m", __func__,
             tr_ipv6(sockaddr.sin6_addr.s6_addr),
             if_indextoname(sockaddr.sin6_scope_id, ifname));
    INFO("tx-udp: %zi bytes", size);
    hexdump(buf, size);
}

int main()
{
    struct sockaddr_in6 sockaddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(IPPORT_ECHO),
    };
    struct pollfd pfd[PFD_COUNT] = { };
    struct in6_addr addr_linklocal;
    struct tun_ctx tun = { };
    struct in6_addr src;
    uint8_t buf[1500];
    int ret, sockfd;
    size_t buf_len;

    tun_init(&tun, true);

    inet_pton(AF_INET6, "fe80::200:5eef:1000:1", addr_linklocal.s6_addr);
    tun_addr_add(&tun, &addr_linklocal, 64);

    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(sockfd < 0, 2, "socket AF_INET6 SOCK_DGRAM IPPROTO_UDP: %m");
    ret = bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    FATAL_ON(ret < 0, 2, "bind: %m");
    ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, tun.ifname, sizeof(tun.ifname));
    FATAL_ON(ret < 0, 2, "setsockopt SO_BINDTODEVICE %s: %m", tun.ifname);

    inet_pton(AF_INET6, "fe80::200:5eef:1000:2", src.s6_addr);
    usleep(1000);

    buf_len = pkt_build_icmp(buf, &src, &addr_linklocal);
    ret = write(tun.fd, buf, buf_len);
    FATAL_ON(ret != buf_len, 2, "write: %m");
    INFO("tx-tun: %zu bytes (icmp echo)", buf_len);
    hexdump(buf, buf_len);

    buf_len = pkt_build_udp(buf, &src, &addr_linklocal);
    ret = write(tun.fd, buf, buf_len);
    FATAL_ON(ret != buf_len, 2, "write: %m");
    INFO("tx-tun: %zu bytes (udp echo)", buf_len);
    hexdump(buf, buf_len);

    pfd[PFD_TUN].fd        = tun.fd;
    pfd[PFD_TUN].events    = POLLIN;
    pfd[PFD_SOCKET].fd     = sockfd;
    pfd[PFD_SOCKET].events = POLLIN;
    while (true) {
        ret = poll(pfd, PFD_COUNT, -1);
        if (pfd[PFD_TUN].revents & POLLIN)
            tun_recv(&tun);
        if (pfd[PFD_SOCKET].revents & POLLIN)
            sock_recv(sockfd);
    }
}
