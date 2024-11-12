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
#include <arpa/inet.h>
#include <sys/random.h>
#include <poll.h>
#include <string.h>

#include "app_wsrd/supplicant/supplicant.h"
#include "common/authenticator/authenticator.h"
#include "common/authenticator/authenticator_radius.h"
#include "common/commandline.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/memutils.h"

struct ctx {
    struct supplicant_ctx supp;
    struct sockaddr_storage supp_addr;
    int supp_fd;

    struct auth_ctx auth;
    int auth_fd;
};

static void supp_sendto_mac(struct supplicant_ctx *supp, uint8_t kmp_id,
                            const void *buf, size_t buf_len, const uint8_t dst[8])
{
    struct ctx *ctx = container_of(supp, struct ctx, supp);
    struct iovec iov[] = {
        { .iov_base = supp->eui64, .iov_len = 8 },
        { .iov_base = &kmp_id,     .iov_len = 1 },
        { .iov_base = (void *)buf, .iov_len = buf_len },
    };
    struct msghdr msg = {
        .msg_iov    = iov,
        .msg_iovlen = 3,
    };
    ssize_t ret;

    ret = sendmsg(ctx->supp_fd, &msg, 0);
    FATAL_ON(ret < 8 + 1 + buf_len, 2, "sendmsg: %m");
}

static uint8_t *supp_get_target(struct supplicant_ctx *supp)
{
    struct ctx *ctx = container_of(supp, struct ctx, supp);

    return ctx->auth.eui64.u8;
}

static void supp_on_gtk_change(struct supplicant_ctx *supp, const uint8_t gtk[16], uint8_t index)
{
    if (gtk)
        INFO("add idx=%u key=%s", index, tr_key(gtk, 16));
    else
        INFO("del idx=%u", index);
}

static void supp_on_failure(struct supplicant_ctx *supp)
{
    INFO("failure");
    exit(EXIT_FAILURE);
}

static void auth_sendto_mac(struct auth_ctx *auth, uint8_t kmp_id,
                            const void *buf, size_t buf_len, const struct eui64 *dst)
{
    struct ctx *ctx = container_of(auth, struct ctx, auth);
    struct iovec iov[] = {
        { .iov_base = (void *)dst, .iov_len = 8 },
        { .iov_base = &kmp_id,     .iov_len = 1 },
        { .iov_base = (void *)buf, .iov_len = buf_len },
    };
    struct msghdr msg = {
        .msg_name    = &ctx->supp_addr,
        .msg_namelen = sizeof(ctx->supp_addr),
        .msg_iov     = iov,
        .msg_iovlen  = 3,
    };
    ssize_t ret;

    ret = sendmsg(ctx->auth_fd, &msg, 0);
    FATAL_ON(ret < 8 + 1 + buf_len, 2, "sendmsg: %m");
}

static void auth_on_supp_gtk_installed(struct auth_ctx *auth, const struct eui64 *eui64, uint8_t index)
{
    INFO("success");
    exit(EXIT_SUCCESS);
}

int main()
{
    const struct eui64 auth_eui64 = { .u8 = { [7] = 1 } };
    const struct eui64 supp_eui64 = { .u8 = { [7] = 2 } };
    struct sockaddr_in6 auth_addr = { };
    struct in6_addr radius_addr = { };
    struct storage_parse_info info;
    struct iovec supp_cert = { };
    struct iovec supp_key = { };
    struct iovec ca_cert = { };
    struct pollfd pfd[4] = { };
    uint8_t buf[2048];
    ssize_t ret;
    struct ctx ctx = {
        .supp.key_request_txalg.rand_min = -0.1,
        .supp.key_request_txalg.irt_s    = 1,
        .supp.key_request_txalg.mrc      = 1,
        .supp.sendto_mac    = supp_sendto_mac,
        .supp.get_target    = supp_get_target,
        .supp.on_gtk_change = supp_on_gtk_change,
        .supp.on_failure    = supp_on_failure,

        .auth.cfg = &(struct auth_cfg){
            .pmk_lifetime_s           = 120,
            .ptk_lifetime_s           = 60,
            .gtk_expire_offset_s      = 30,
            .gtk_new_activation_time  = 720,
            .gtk_new_install_required = 80,
        },
        .auth.sendto_mac            = auth_sendto_mac,
        .auth.on_supp_gtk_installed = auth_on_supp_gtk_installed,
        .auth.radius_fd  = -1,
    };

    g_enabled_traces |= TR_DROP;
    g_enabled_traces |= TR_SECURITY;

    strcpy(info.value, "/usr/local/share/doc/wsbrd/examples/ca_cert.pem");
    conf_set_pem(&info, &ca_cert, NULL);
    strcpy(info.value, "/usr/local/share/doc/wsbrd/examples/node_cert.pem");
    conf_set_pem(&info, &supp_cert, NULL);
    strcpy(info.value, "/usr/local/share/doc/wsbrd/examples/node_key.pem");
    conf_set_pem(&info, &supp_key, NULL);
    supp_init(&ctx.supp, &ca_cert, &supp_cert, &supp_key, supp_eui64.u8);
    supp_reset(&ctx.supp);

    strcpy(ctx.auth.radius_secret, "SHARED_SECRET");
    inet_pton(AF_INET6, "::1", &radius_addr);
    radius_init(&ctx.auth, &radius_addr);
    auth_start(&ctx.auth, &auth_eui64);

    supp_start_key_request(&ctx.supp);

    ctx.auth_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(ctx.supp_fd < 0, 2, "socket: %m");
    auth_addr.sin6_family = AF_INET6;
    auth_addr.sin6_addr = in6addr_loopback;
    auth_addr.sin6_port = htons(10000);
    ret = bind(ctx.auth_fd, (struct sockaddr *)&auth_addr, sizeof(auth_addr));
    FATAL_ON(ret < 0, 2, "bind: %m");

    ctx.supp_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(ctx.supp_fd < 0, 2, "socket: %m");
    ret = connect(ctx.supp_fd, (struct sockaddr *)&auth_addr, sizeof(auth_addr));
    FATAL_ON(ret < 0, 2, "connect: %m");
    ret = getsockname(ctx.supp_fd, (struct sockaddr *)&ctx.supp_addr,
                      (socklen_t[1]){ sizeof(ctx.supp_addr) });
    FATAL_ON(ret < 0, 2, "getsockname: %m");

    pfd[0].fd = timer_fd();
    pfd[0].events = POLLIN;
    pfd[1].fd = ctx.auth.radius_fd;
    pfd[1].events = POLLIN;
    pfd[2].fd = ctx.auth_fd;
    pfd[2].events = POLLIN;
    pfd[3].fd = ctx.supp_fd;
    pfd[3].events = POLLIN;
    while (1) {
        ret = poll(pfd, 4, -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (pfd[0].revents & POLLIN)
            timer_process();
        if (pfd[1].revents & POLLIN)
            radius_recv(&ctx.auth);
        if (pfd[2].revents & POLLIN) {
            ret = recv(ctx.auth_fd, buf, sizeof(buf), 0);
            FATAL_ON(ret < 8 + 1, 2, "recv: %m");
            auth_recv_eapol(&ctx.auth, buf[8], (struct eui64 *)buf,
                            buf + 8 + 1, ret - 8 - 1);
        }
        if (pfd[3].revents & POLLIN) {
            ret = recv(ctx.supp_fd, buf, sizeof(buf), 0);
            FATAL_ON(ret < 8 + 1, 2, "recv: %m");
            supp_recv_eapol(&ctx.supp, buf[8],
                            buf + 8 + 1, ret - 8 - 1,
                            ctx.auth.eui64.u8);
        }
    }
}
