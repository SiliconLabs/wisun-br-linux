/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdbool.h>
#include <backtrace.h>

static int backtrace_cb(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
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

    printf("Backtrace:\n");
    backtrace_full(state, 1, backtrace_cb, NULL, NULL);
}
