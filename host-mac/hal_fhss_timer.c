/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <time.h>
#include <sys/timerfd.h>

#include "hal_fhss_timer.h"
#include "host-common/os_types.h"
#include "host-common/slist.h"
#include "host-common/log.h"

static int fhss_timer_start(uint32_t slots_us, void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *api)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    struct fhss_timer_entry *item;
    struct itimerspec timer = {
        .it_value.tv_sec = slots_us / 1000000,
        .it_value.tv_nsec = slots_us % 1000000 * 1000,
    };
    int ret;

    SLIST_FOR_EACH_ENTRY(ctxt->fhss_timers, item, node)
        if (item->fn == callback)
            break;
    // Take care with compiler optimization with pointer arithmetic. This
    // expression is know to work. "!&(item->node)" does not work.
    if (item == container_of(NULL, typeof(*item), node)) {
        item = calloc(1, sizeof(struct fhss_timer));
        item->fn = callback;
        item->arg = api;
        item->fd = timerfd_create(CLOCK_MONOTONIC, 0);
        FATAL_ON(item->fd < 0, 2);
        FATAL_ON(item->fd > 255, 2);
        slist_push(&ctxt->fhss_timers, &item->node);
    }
    ret = timerfd_settime(item->fd, 0, &timer, NULL);
    FATAL_ON(ret < 0, 2);
    return 0;
}

static int fhss_timer_stop(void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *api)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    struct fhss_timer_entry *item;
    struct itimerspec timer = { };
    int ret;

    SLIST_FOR_EACH_ENTRY(ctxt->fhss_timers, item, node) {
        if (item->fn == callback) {
            ret = timerfd_settime(item->fd, 0, &timer, NULL);
            FATAL_ON(ret < 0, 2);
            return 0;
        }
    }
    return -1;
}

static uint32_t fhss_get_remaining_slots(void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *api)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    struct fhss_timer_entry *item;
    struct itimerspec timer;
    int ret;

    SLIST_FOR_EACH_ENTRY(ctxt->fhss_timers, item, node) {
        if (item->fn == callback) {
            ret = timerfd_gettime(item->fd, &timer);
            FATAL_ON(ret < 0, 2);
            return timer.it_value.tv_sec * 1000000 + timer.it_value.tv_nsec / 1000;
        }
    }
    return -1;
}

static uint32_t fhss_get_timestamp(const fhss_api_t *api)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);
    return tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
}

struct fhss_timer wsmac_fhss = {
    .fhss_timer_start         = fhss_timer_start,
    .fhss_timer_stop          = fhss_timer_stop,
    .fhss_get_remaining_slots = fhss_get_remaining_slots,
    .fhss_get_timestamp       = fhss_get_timestamp,
    .fhss_resolution_divider  = 1
};
