/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2026 Silicon Laboratories Inc. (www.silabs.com)
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
#include <mosquitto.h>
#include <poll.h>

#include "tools/silabs-ws-auth/commandline.h"
#include "common/specs/sl_auth.h"
#include "common/ws/eapol_relay.h"
#include "common/config.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/mqtt.h"
#include "common/version.h"

enum {
    POLLFD_EAPOL_RELAY,
    POLLFD_TIMER,
    POLLFD_MQTT,
    POLLFD_COUNT,
};

struct sl_auth_ctx {
    struct sl_auth_cfg cfg;
    struct auth_ctx auth;
    struct mqtt_ctx mqtt;
};

static void sl_auth_publish(struct sl_auth_ctx *ctx)
{
    struct sl_auth_mqtt_info info = {
        .eui64 = ctx->cfg.eui64,
        .gtk_index = ctx->auth.gtk_group.slot_active + 1,
        .lgtk_index = ctx->auth.lgtk_group.slot_active + 1,
    };
    int ret;

    for (int i = 0; i < WS_GTK_COUNT + WS_LGTK_COUNT; i++) {
        if (timer_stopped(&ctx->auth.gtks[i].expiration_timer))
            continue;
        memcpy(&info.gtk[i], ctx->auth.gtks[i].key, 16);
    }

    ret = mosquitto_publish(ctx->mqtt.mosq, NULL, "gtks", sizeof(info), &info, 1, true);
    WARN_ON(ret, "mosquitto_publish: %s", mosquitto_strerror(ret));
}

static void sl_auth_on_gtk_change(struct auth_ctx *auth,
                                  uint8_t removed_mask,
                                  uint8_t installed_mask,
                                  uint8_t activated_mask)
{
    struct sl_auth_ctx *ctx = container_of(auth, struct sl_auth_ctx, auth);

    sl_auth_publish(ctx);
}

static void sl_auth_recv(struct sl_auth_ctx *ctx)
{
    struct auth_supp_ctx *supp;
    struct eui64 supp_eui64;
    struct in6_addr src;
    uint8_t buf[1500];
    ssize_t buf_len;
    uint8_t kmp_id;

    buf_len = eapol_relay_recv(ctx->auth.eapol_relay_fd, buf, sizeof(buf),
                               &src, &supp_eui64, &kmp_id);
    if (buf_len < 0)
        return;

    supp = auth_fetch_supp(&ctx->auth, &supp_eui64);
    supp->eapol_target = src;
    auth_recv_eapol(&ctx->auth, kmp_id, &supp_eui64, buf, buf_len);
}

int main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    struct sl_auth_ctx ctx = {
        .auth.on_gtk_change = sl_auth_on_gtk_change,
        .auth.cfg = &ctx.cfg.auth,
        .auth.radius_fd = -1,
        .auth.timeout_ms = 30 * 1000, // Arbitrary
        .mqtt.keepalive.period_ms = 60 * 1000, // Arbitrary
    };
    int ret;

    INFO("Silicon Labs Wi-SUN Authenticator %s", version_daemon_str);
    parse_commandline(&ctx.cfg, argc, argv);

    if (ctx.cfg.storage_delete) {
        INFO("deleting storage");
        storage_delete((const char *[]){ "network-keys", "supp-*", NULL });
        if (ctx.cfg.storage_exit)
            return EXIT_SUCCESS;
    }

    mqtt_start(&ctx.mqtt, "::1");

    ctx.auth.eapol_relay_fd = eapol_relay_start("lo");
    auth_start(&ctx.auth, &ctx.cfg.eui64, ctx.cfg.enable_lfn);

    pfd[POLLFD_EAPOL_RELAY].events = POLLIN;
    pfd[POLLFD_EAPOL_RELAY].fd = ctx.auth.eapol_relay_fd;
    pfd[POLLFD_TIMER].events = POLLIN;
    pfd[POLLFD_TIMER].fd = timer_fd();

    while (1) {
        pfd[POLLFD_MQTT].fd = mqtt_fd(&ctx.mqtt);
        pfd[POLLFD_MQTT].events = mqtt_events(&ctx.mqtt);

        ret = poll(pfd, POLLFD_COUNT, -1);
        FATAL_ON(ret < 0, 2, "poll: %m");

        if (pfd[POLLFD_TIMER].revents & POLLIN)
            timer_process();
        if (pfd[POLLFD_EAPOL_RELAY].revents & POLLIN)
            sl_auth_recv(&ctx);
        if (pfd[POLLFD_MQTT].revents)
            mqtt_process(&ctx.mqtt, pfd[POLLFD_MQTT].revents);
    }
}
