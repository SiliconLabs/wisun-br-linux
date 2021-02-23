/*
 * License: GPLv2
 * Created: 2021-02-03 14:57:18
 * Copyright 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef HAL_FHSS_TIMER_H
#define HAL_FHSS_TIMER_H

#include "fhss_config.h"
#include "slist.h"

struct fhss_timer_entry {
    int fd;
    const fhss_api_t *arg;
    void (*fn)(const fhss_api_t *api, uint16_t);
    struct slist node;
};

extern struct fhss_timer wsbr_fhss;

#endif
