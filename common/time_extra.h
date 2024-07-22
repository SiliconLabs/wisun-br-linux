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
#ifndef TIME_EXTRA_H
#define TIME_EXTRA_H
#include <stdint.h>
#include <time.h>

time_t time_now_s(clockid_t clockid);

uint64_t time_now_ms(void);

time_t time_get_elapsed(clockid_t clockid, time_t start);

/*
 * We rely on monotonic clock everywhere. However, monotonic timestamps do
 * not survive to reboots. So timestamp stored on the disk must use realtime
 * timestamps.
 * This function computes the rough delta between monotonic and realtime. It
 * should be used to write/read timestamps to/from the disk:
 * - Add returned value to a monotonic timestamp to get a realtime date
 * - Substract returned value from a realtime date to get a monotonic timestamp
 */
time_t time_get_storage_offset(void);

#endif /* TIME_EXTRA_H */
