/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_DBUS_H
#define WSBR_DBUS_H

struct wsbr_ctxt;

#ifdef HAVE_LIBSYSTEMD

void dbus_emit_keys_change(struct wsbr_ctxt *ctxt);
void dbus_emit_nodes_change(struct wsbr_ctxt *ctxt);
void dbus_emit_routing_graph_change(struct wsbr_ctxt *ctxt);
void dbus_register(struct wsbr_ctxt *ctxt);
int dbus_get_fd(struct wsbr_ctxt *ctxt);
int dbus_process(struct wsbr_ctxt *ctxt);

#else

#include "common/log.h"

static inline void dbus_emit_keys_change(struct wsbr_ctxt *ctxt)
{
}

static inline void dbus_emit_nodes_change(struct wsbr_ctxt *ctxt)
{
    /* empty */
}

static inline void dbus_emit_routing_graph_change(struct wsbr_ctxt *ctxt)
{
    /* empty */
}

static inline void dbus_register(struct wsbr_ctxt *ctxt)
{
    WARN("support for DBus is disabled");
}

static inline int dbus_get_fd(struct wsbr_ctxt *ctxt)
{
    return -1;
}

static inline int dbus_process(struct wsbr_ctxt *ctxt)
{
    return 0;
}

#endif

#endif
