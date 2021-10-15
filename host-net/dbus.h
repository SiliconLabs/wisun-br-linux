/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_DBUS_H
#define WSBR_DBUS_H

struct wsbr_ctxt;

#ifdef HAVE_LIBSYSTEMD

void dbus_register(struct wsbr_ctxt *ctxt);
int dbus_get_fd(struct wsbr_ctxt *ctxt);
int dbus_process(struct wsbr_ctxt *ctxt);

#else

static void dbus_register(struct wsbr_ctxt *ctxt)
{
}

static int dbus_get_fd(struct wsbr_ctxt *ctxt)
{
    return -1;
}

static int dbus_process(struct wsbr_ctxt *ctxt)
{
    return 0;
}

#endif

#endif
