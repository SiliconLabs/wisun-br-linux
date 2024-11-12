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
    struct auth_ctx auth;
};

static void supp_sendto_mac(struct supplicant_ctx *supp, uint8_t kmp_id,
                            const void *buf, size_t buf_len, const uint8_t dst[8])
{
    struct ctx *ctx = container_of(supp, struct ctx, supp);

    auth_recv_eapol(&ctx->auth, kmp_id, (struct eui64 *)supp->eui64, buf, buf_len);
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

    supp_recv_eapol(&ctx->supp, kmp_id, buf, buf_len, auth->eui64.u8);
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
    struct in6_addr radius_addr = { };
    struct storage_parse_info info;
    struct iovec supp_cert = { };
    struct iovec supp_key = { };
    struct iovec ca_cert = { };
    struct pollfd pfd[2] = { };
    int ret;
    struct ctx ctx = {
        .supp.key_request_txalg.rand_min = -0.1,
        .supp.key_request_txalg.irt_s    = 1,
        .supp.key_request_txalg.mrc      = 1,
        .supp.sendto_mac    = supp_sendto_mac,
        .supp.get_target    = supp_get_target,
        .supp.on_gtk_change = supp_on_gtk_change,
        .supp.on_failure    = supp_on_failure,

        .auth.cfg = &(struct auth_cfg){
            .ptk_lifetime_s           = 120,
            .gtk_expire_offset_s      = 60,
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

    pfd[0].fd = timer_fd();
    pfd[0].events = POLLIN;
    pfd[1].fd = ctx.auth.radius_fd;
    pfd[1].events = POLLIN;
    while (1) {
        ret = poll(pfd, 2, -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (pfd[0].revents & POLLIN)
            timer_process();
        if (pfd[1].revents & POLLIN)
            radius_recv(&ctx.auth);
    }
}
