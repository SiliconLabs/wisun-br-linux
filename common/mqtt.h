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

struct mosquitto;

struct mqtt_ctx {
    struct mosquitto *mosq;
};

#ifdef HAVE_MQTT
void mqtt_start(struct mqtt_ctx *mqtt, const char *host);
int mqtt_fd(const struct mqtt_ctx *mqtt);
int mqtt_events(const struct mqtt_ctx *mqtt);
void mqtt_process(const struct mqtt_ctx *mqtt, int revents);
#else
#include "common/log.h"

static inline void mqtt_start(struct mqtt_ctx *mqtt, const char *host)
{
    FATAL(1, "libmosquitto support is disabled");
}

static inline int mqtt_fd(const struct mqtt_ctx *mqtt)
{
    return -1;
}

static inline int mqtt_events(const struct mqtt_ctx *mqtt)
{
    return 0;
}

static inline void mqtt_process(const struct mqtt_ctx *mqtt, int revents)
{
    // empty
}
#endif

#endif
