/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef OS_SCHEDULER_H
#define OS_SCHEDULER_H

#include "nanostack-event-loop/eventOS_scheduler.h"

struct os_ctxt;

void eventOS_scheduler_os_init(struct os_ctxt *ctxt);

#endif

