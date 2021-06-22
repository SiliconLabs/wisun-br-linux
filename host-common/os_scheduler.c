/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <unistd.h>
#include <stdio.h>

#include "os_scheduler.h"
#include "os_types.h"
#include "log.h"

void eventOS_scheduler_signal(void)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    uint64_t val = 'W';

    write(ctxt->event_fd[1], &val, sizeof(val));
}

void eventOS_scheduler_idle(void)
{
    // eventOS_scheduler_idle() is only called by eventOS_scheduler_run() and it
    // makes no sense to use this function on Linux
    BUG("Not implemented");
}
