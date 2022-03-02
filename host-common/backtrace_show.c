/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
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
            printf("  %016lx ??\n", (unsigned long)pc);
        else if (!filename)
            printf("  %016lx %s() at ??\n", (unsigned long)pc, function);
        else
            printf("  %016lx %s() at %s:%d\n", (unsigned long)pc, function, filename, lineno);
    } else {
        if (!function)
            printf("  %08lx ??\n", (unsigned long)pc);
        else if (!filename)
            printf("  %08lx %s() at ??\n", (unsigned long)pc, function);
        else
            printf("  %08lx %s() at %s:%d\n", (unsigned long)pc, function, filename, lineno);
    }
    return 0;
}

void backtrace_show() {
    struct backtrace_state *state = backtrace_create_state(NULL, false, NULL, NULL);

    if (state) {
        printf("Backtrace:\n");
        backtrace_full(state, 1, backtrace_cb, NULL, NULL);
    } else {
        printf("Backtrace not available\n");
    }
}
