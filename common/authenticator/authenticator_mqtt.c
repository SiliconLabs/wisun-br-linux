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
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "common/authenticator/authenticator.h"
#include "common/ws/eapol_relay.h"
#include "common/specs/sl_auth.h"
#include "common/string_extra.h"
#include "common/memutils.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/mqtt.h"

#include "authenticator_mqtt.h"

static void auth_mqtt_recv_cb(struct mosquitto *mosq, void *obj,
                              const struct mosquitto_message *msg)
{
    struct auth_ctx *auth = container_of(obj, struct auth_ctx, mqtt);
    uint8_t removed, installed, activated;
    const struct sl_auth_mqtt_info *info;

    if (strcmp(msg->topic, "gtks")) {
        TRACE(TR_DROP, "drop %-9s: unsupported topic %s", "mqtt", msg->topic);
        return;
    }
    if (msg->payloadlen < sizeof(struct sl_auth_mqtt_info)) {
        TRACE(TR_DROP, "drop %-9s: malformed payload", "mqtt");
        return;
    }
    info = msg->payload;
    auth->eui64 = info->eui64;
    removed = installed = activated = 0;
    for (int i = 0; i < WS_GTK_COUNT + WS_LGTK_COUNT; i++) {
        if (!memcmp(auth->gtks[i].key, info->gtk[i], 16))
            continue;
        if (!memzcmp(info->gtk[i], 16)) {
            removed |= BIT(i);
            ws_gtk_clear(&auth->timer_group, &auth->gtks[i]);
        } else {
            installed |= BIT(i);
            ws_gtk_clear(&auth->timer_group, &auth->gtks[i]);
            memcpy(auth->gtks[i].key, info->gtk[i], 16);
            timer_start_abs(&auth->timer_group, &auth->gtks[i].expiration_timer, UINT64_MAX);
        }
    }
    if (info->gtk_index != auth->gtk_group.slot_active + 1) {
        auth->gtk_group.slot_active = info->gtk_index - 1;
        activated |= BIT(auth->gtk_group.slot_active);
    }
    if (info->lgtk_index != auth->lgtk_group.slot_active + 1) {
        auth->lgtk_group.slot_active = info->lgtk_index - 1;
        activated |= BIT(auth->lgtk_group.slot_active);
    }
    if (removed || installed || activated)
        auth->on_gtk_change(auth, removed, installed, activated);
}

static void auth_mqtt_resolve6(const char *host, struct in6_addr *addr)
{
    const struct addrinfo hints = {
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
        .ai_flags = AI_ADDRCONFIG,
    };
    struct sockaddr_in6 *sin6;
    struct addrinfo *ai;
    int ret;

    ret = getaddrinfo(host, NULL, &hints, &ai);
    FATAL_ON(ret, 1, "getaddrinfo %s: %s", host, gai_strerror(ret));
    sin6 = (struct sockaddr_in6 *)ai[0].ai_addr;
    *addr = sin6->sin6_addr;
    freeaddrinfo(ai);
}

void auth_mqtt_start(struct auth_ctx *auth, const char *host)
{
    struct pollfd pfd = { };
    uint64_t t0;
    int ret;

    auth_mqtt_resolve6(host, &auth->ext_auth_addr);
    mqtt_start(&auth->mqtt, host);

    mosquitto_message_callback_set(auth->mqtt.mosq, auth_mqtt_recv_cb);
    ret = mosquitto_subscribe(auth->mqtt.mosq, NULL, "gtks", 1);
    FATAL_ON(ret, 2, "mosquitto_subscribe: %s", mosquitto_strerror(ret));

    // NOTE: Force new active key in on_gtk_change() 1st call
    auth->gtk_group.slot_active = -1;
    auth->lgtk_group.slot_active = -1;

    t0 = time_now_ms(CLOCK_MONOTONIC);
    while (true) {
        pfd.fd = mqtt_fd(&auth->mqtt);
        pfd.events = mqtt_events(&auth->mqtt);

        ret = poll(&pfd, 1, t0 ? 1000 : -1);
        FATAL_ON(ret < 0, 2, "poll: %m");

        mqtt_process(&auth->mqtt, pfd.revents);

        for (int i = 0; i < WS_GTK_COUNT + WS_LGTK_COUNT; i++)
            if (!timer_stopped(&auth->gtks[i].expiration_timer))
                return;
        if (t0 && time_now_ms(CLOCK_MONOTONIC) > t0 + 1000) {
            WARN("waiting for gtks from MQTT broker");
            t0 = 0;
        }
    }
}

void auth_mqtt_recv_eapol(struct auth_ctx *auth,
                          const struct eui64 *supp_eui64, uint8_t kmp_id,
                          const void *buf, size_t buf_len)
{
    auth_fetch_supp(auth, supp_eui64);
    eapol_relay_send(auth->eapol_relay_fd, buf, buf_len,
                     &auth->ext_auth_addr, supp_eui64, kmp_id);
}

void auth_mqtt_recv_eapol_relay(struct auth_ctx *auth,
                                const struct in6_addr *src,
                                struct eui64 *supp_eui64, uint8_t kmp_id,
                                const void *buf, size_t buf_len)
{
    struct auth_supp_ctx *supp;

    if (IN6_ARE_ADDR_EQUAL(src, &auth->ext_auth_addr)) {
        supp = auth_get_supp(auth, supp_eui64);
        if (!supp) {
            TRACE(TR_DROP, "drop %-9s: unknown supp=%s",
                  "eapol-rel", tr_eui64(supp_eui64->u8));
            return;
        }
        auth_send_eapol(auth, supp, kmp_id, buf, buf_len);
    } else {
        supp = auth_fetch_supp(auth, supp_eui64);
        supp->eapol_target = *src;
        eapol_relay_send(auth->eapol_relay_fd, buf, buf_len,
                         &auth->ext_auth_addr, supp_eui64, kmp_id);
    }
}
