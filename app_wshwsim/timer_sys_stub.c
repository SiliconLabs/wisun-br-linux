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
#include "common/log.h"
#include "stack-scheduler/eventOS_event.h"

void timer_sys_event_free(arm_event_storage_t *event)
{
    BUG("Not supported");
}

void timer_sys_event_cancel_critical(struct arm_event_storage *event)
{
    BUG("Not supported");
}
