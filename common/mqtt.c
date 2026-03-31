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
#include "common/log.h"

#include "mqtt.h"

#ifdef HAVE_MQTT
#include <mosquitto.h>
#include <poll.h>

#include "common/memutils.h"

static void mqtt_log_cb(struct mosquitto *mosq, void *obj,
                        int level, const char *str)
{
    TRACE(TR_MQTT, "mqtt: %s", str);
}

static void mqtt_keepalive(struct timer_group *group, struct timer_entry *timer)
{
    struct mqtt_ctx *mqtt = container_of(timer, struct mqtt_ctx, keepalive);
    int ret;

    ret = mosquitto_loop_misc(mqtt->mosq);
    WARN_ON(ret, "mosquitto_loop_misc: %s", mosquitto_strerror(ret));
}

static void mqtt_connect_cb(struct mosquitto *mosq, void *obj, int rc)
{
    struct mqtt_ctx *mqtt = obj;

    mqtt->connected = !rc;
    FATAL_ON(!mqtt->connected, 2, "mqtt: %s", mosquitto_connack_string(rc));
}

static void mqtt_disconnect_cb(struct mosquitto *mosq, void *obj, int rc)
{
    FATAL(2, "mqtt disconnected: %s", mosquitto_strerror(rc));
}

void mqtt_start(struct mqtt_ctx *mqtt, const char *host)
{
    struct pollfd pfd = { };
    int ret;

    mosquitto_lib_init();
    mqtt->mosq = mosquitto_new(NULL, true, mqtt);
    FATAL_ON(!mqtt->mosq, 2, "mosquitto_new: %m");
    mosquitto_connect_callback_set(mqtt->mosq, mqtt_connect_cb);
    mosquitto_disconnect_callback_set(mqtt->mosq, mqtt_disconnect_cb);
    mosquitto_log_callback_set(mqtt->mosq, mqtt_log_cb);
    ret = mosquitto_connect(mqtt->mosq, host, 1883,
                            mqtt->keepalive.period_ms / 1000);
    FATAL_ON(ret, 2, "mosquitto_connect %s: %s", host, mosquitto_strerror(ret));

    while (!mqtt->connected) {
        pfd.fd = mqtt_fd(mqtt);
        pfd.events = mqtt_events(mqtt);
        ret = poll(&pfd, 1, -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        mqtt_process(mqtt, pfd.revents);
    }

    BUG_ON(!mqtt->keepalive.period_ms);
    mqtt->keepalive.callback = mqtt_keepalive;
    timer_start_rel(NULL, &mqtt->keepalive, mqtt->keepalive.period_ms);
}

int mqtt_fd(const struct mqtt_ctx *mqtt)
{
    if (!mqtt->mosq)
        return -1;
    return mosquitto_socket(mqtt->mosq);
}

int mqtt_events(const struct mqtt_ctx *mqtt)
{
    if (!mqtt->mosq)
        return 0;
    if (mosquitto_want_write(mqtt->mosq))
        return POLLIN | POLLOUT;
    else
        return POLLIN;
}

void mqtt_process(const struct mqtt_ctx *mqtt, int revents)
{
    int ret;

    if (revents & POLLOUT) {
        ret = mosquitto_loop_write(mqtt->mosq, 1);
        WARN_ON(ret, "mosquitto_loop_write: %s", mosquitto_strerror(ret));
    }
    if (revents & POLLIN) {
        ret = mosquitto_loop_read(mqtt->mosq, 1);
        WARN_ON(ret, "mosquitto_loop_read: %s", mosquitto_strerror(ret));
    }
}
#else
void mqtt_start(struct mqtt_ctx *mqtt, const char *host)
{
    FATAL(1, "libmosquitto support is disabled");
}

int mqtt_fd(const struct mqtt_ctx *mqtt)
{
    return -1;
}

int mqtt_events(const struct mqtt_ctx *mqtt)
{
    return 0;
}

void mqtt_process(const struct mqtt_ctx *mqtt, int revents)
{
    BUG();
}
#endif
