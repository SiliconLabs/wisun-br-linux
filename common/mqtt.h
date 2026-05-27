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
#ifndef MQTT_H
#define MQTT_H
#include <stdbool.h>
#include <limits.h>

#include "common/config.h"
#include "common/timer.h"

struct mosquitto;

struct mqtt_ctx {
    struct mosquitto *mosq;
    struct timer_entry keepalive;
    bool connected;

    // Called on (re-)connection. Clients should subscribe or publish there.
    void (*on_connected)(struct mqtt_ctx *mqtt);
};

struct mqtt_cfg {
    char broker[256];
    char ca[PATH_MAX];
    char cert[PATH_MAX];
    char key[PATH_MAX];
};

extern const struct option_struct mqtt_opts[];

void mqtt_start(struct mqtt_ctx *mqtt, const struct mqtt_cfg *cfg);
int mqtt_fd(const struct mqtt_ctx *mqtt);
int mqtt_events(const struct mqtt_ctx *mqtt);
void mqtt_process(const struct mqtt_ctx *mqtt, int revents);

#endif
