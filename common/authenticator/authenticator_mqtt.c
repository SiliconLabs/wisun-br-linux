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
#include <poll.h>

#include "common/authenticator/authenticator.h"
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

void auth_mqtt_start(struct auth_ctx *auth, const char *host)
{
    int ret;

    mqtt_start(&auth->mqtt, host);

    mosquitto_message_callback_set(auth->mqtt.mosq, auth_mqtt_recv_cb);
    ret = mosquitto_subscribe(auth->mqtt.mosq, NULL, "gtks", 1);
    FATAL_ON(ret, 2, "mosquitto_subscribe: %s", mosquitto_strerror(ret));

    // NOTE: Force new active key in on_gtk_change() 1st call
    auth->gtk_group.slot_active = -1;
    auth->lgtk_group.slot_active = -1;
}
