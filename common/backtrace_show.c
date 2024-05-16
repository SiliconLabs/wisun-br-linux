/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <backtrace.h>

#ifdef HAVE_LIBDL
#include <dlfcn.h>
#endif

static const char *get_symbol_with_libdl(uintptr_t pc)
{
#ifdef HAVE_LIBDL
        Dl_info info;

        if (dladdr((void *)pc, &info))
            return info.dli_sname;
#endif
        return NULL;
}

static int backtrace_cb(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
    if (!function)
        function = get_symbol_with_libdl(pc);

    if (sizeof(void *) > 4) {
        if (!function)
            fprintf(stderr, "  %016lx ??\n", (unsigned long)pc);
        else if (!filename)
            fprintf(stderr, "  %016lx %s() at ??\n", (unsigned long)pc, function);
        else
            fprintf(stderr, "  %016lx %s() at %s:%d\n", (unsigned long)pc, function, filename, lineno);
    } else {
        if (!function)
            fprintf(stderr, "  %08lx ??\n", (unsigned long)pc);
        else if (!filename)
            fprintf(stderr, "  %08lx %s() at ??\n", (unsigned long)pc, function);
        else
            fprintf(stderr, "  %08lx %s() at %s:%d\n", (unsigned long)pc, function, filename, lineno);
    }
    return 0;
}

void backtrace_show() {
    struct backtrace_state *state = backtrace_create_state(NULL, false, NULL, NULL);

    if (state) {
        fprintf(stderr, "Backtrace:\n");
        backtrace_full(state, 1, backtrace_cb, NULL, NULL);
    } else {
        fprintf(stderr, "Backtrace not available\n");
    }
}
