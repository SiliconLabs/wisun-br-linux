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

#include "common/log.h"

#include "mqtt.h"

static void mqtt_log_cb(struct mosquitto *mosq, void *obj,
                        int level, const char *str)
{
    TRACE(TR_MQTT, "mqtt: %s", str);
}

void mqtt_start(struct mqtt_ctx *mqtt, const char *host)
{
    int ret;

    mosquitto_lib_init();
    mqtt->mosq = mosquitto_new(NULL, true, mqtt);
    FATAL_ON(!mqtt->mosq, 2, "mosquitto_new: %m");
    mosquitto_log_callback_set(mqtt->mosq, mqtt_log_cb);
    ret = mosquitto_connect(mqtt->mosq, host, 1883, 60);
    FATAL_ON(ret, 2, "mosquitto_connect %s: %s", host, mosquitto_strerror(ret));
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
