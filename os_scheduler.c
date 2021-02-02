/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <unistd.h>
#include <stdio.h>

#include "os_scheduler.h"
#include "wsbr.h"

void eventOS_scheduler_signal(void)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    write(ctxt->event_fd[1], "W", 1);
}

void eventOS_scheduler_idle(void)
{
    printf("%s: FIXME\n", __func__);
}
