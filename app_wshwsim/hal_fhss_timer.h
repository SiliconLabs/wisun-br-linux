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
#ifndef HAL_FHSS_TIMER_H
#define HAL_FHSS_TIMER_H

#include "common/slist.h"
#include "stack/mac/fhss_config.h"

struct fhss_timer_entry {
    int fd;
    const fhss_api_t *arg;
    void (*fn)(const fhss_api_t *api, uint16_t);
    struct slist node;
};

extern struct fhss_timer wsmac_fhss;

#endif
