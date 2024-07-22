/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdint.h>
#include <time.h>

time_t time_current(clockid_t clockid)
{
    struct timespec tp;

    clock_gettime(clockid, &tp);
    return tp.tv_sec;
}

uint64_t time_now_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

time_t time_get_elapsed(clockid_t clockid, time_t start)
{
    struct timespec tp;

    clock_gettime(clockid, &tp);
    return tp.tv_sec - start;
}

time_t time_get_storage_offset(void)
{
    struct timespec tp_realtime, tp_monotonic;

    clock_gettime(CLOCK_REALTIME, &tp_realtime);
    clock_gettime(CLOCK_MONOTONIC, &tp_monotonic);
    return tp_realtime.tv_sec - tp_monotonic.tv_sec;
}
