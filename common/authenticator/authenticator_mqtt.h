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
#ifndef AUTHENTICATOR_MQTT_H
#define AUTHENTICATOR_MQTT_H
#include <stddef.h>
#include <stdint.h>

struct auth_ctx;
struct in6_addr;
struct eui64;

/*
 * Stub the authenticator key mananagement with a MQTT broker responsible for
 * informing the border router of key installation, removal, and activation.
 */

#ifdef HAVE_AUTH_MQTT
void auth_mqtt_start(struct auth_ctx *auth, const char *host);
void auth_mqtt_recv_eapol(struct auth_ctx *auth,
                          const struct eui64 *supp_eui64, uint8_t kmp_id,
                          const void *buf, size_t buf_len);
void auth_mqtt_recv_eapol_relay(struct auth_ctx *auth,
                                const struct in6_addr *src,
                                struct eui64 *supp_eui64, uint8_t kmp_id,
                                const void *buf, size_t buf_len);
#else
#include "common/log.h"

static inline void auth_mqtt_start(struct auth_ctx *auth, const char *host)
{
    FATAL(1, "mqtt_broker requires libmosquitto");
}

static inline void auth_mqtt_recv_eapol(struct auth_ctx *auth,
                                        const struct eui64 *supp_eui64, uint8_t kmp_id,
                                        const void *buf, size_t buf_len)
{
    BUG();
}

static inline void auth_mqtt_recv_eapol_relay(struct auth_ctx *auth,
                                              const struct in6_addr *src,
                                              struct eui64 *supp_eui64, uint8_t kmp_id,
                                              const void *buf, size_t buf_len)
{
    BUG();
}
#endif

#endif
