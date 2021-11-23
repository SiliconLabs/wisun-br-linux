/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#include "os_scheduler.h"
#include "os_types.h"
#include "log.h"

void eventOS_scheduler_os_init(struct os_ctxt *ctxt)
{
    pipe(ctxt->event_fd);
    fcntl(ctxt->event_fd[1], F_SETPIPE_SZ, sizeof(uint64_t) * 2);
    fcntl(ctxt->event_fd[1], F_SETFL, O_NONBLOCK);
}

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
