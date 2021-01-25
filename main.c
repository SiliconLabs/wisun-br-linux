/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_interrupt.h"
#include "net_interface.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

int main(int argc, char *argv[])
{
    platform_critical_init();
    mbed_trace_init();

    if (net_init_core())
        tr_err("%s: net_init_core", __func__);

    return 0;
}

