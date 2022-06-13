/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
