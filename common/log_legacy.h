/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef LOG_LEGACY_H
#define LOG_LEGACY_H
#include "common/log.h"

#define tr_debug(MSG, ...) __PRINT(90, "[DBG ][%-4s]: " MSG, TRACE_GROUP, ##__VA_ARGS__)
#define tr_info(MSG, ...)  __PRINT(39, "[INFO][%-4s]: " MSG, TRACE_GROUP, ##__VA_ARGS__)
#define tr_warn(MSG, ...)  __PRINT(33, "[WARN][%-4s]: " MSG, TRACE_GROUP, ##__VA_ARGS__)
#define tr_error(MSG, ...) __PRINT(31, "[ERR ][%-4s]: " MSG, TRACE_GROUP, ##__VA_ARGS__)

#define trace_array       tr_key

static inline void vtracef(uint8_t dlevel, const char *grp, const char *fmt, va_list ap)
{
    if (dlevel == 0 && g_enable_color_traces)
        fprintf(g_trace_stream, "\x1b[90m[DBG ][%-4s]:", grp);
    else if (dlevel == 0)
        fprintf(g_trace_stream, "[DBG ][%-4s]:", grp);
    else
        fprintf(g_trace_stream, "[INFO][%-4s]:", grp);
    vfprintf(g_trace_stream, fmt, ap);
    if (dlevel == 0 && g_enable_color_traces)
        fprintf(g_trace_stream, "\x1b[0m");
    fprintf(g_trace_stream, "\n");
}

#endif
