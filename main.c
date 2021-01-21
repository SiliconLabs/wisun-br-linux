/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_interrupt.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

int main(int argc, char *argv[])
{
    platform_critical_init();
    mbed_trace_init();
    tr_debug("this is debug msg");
    tr_info("this is info msg");
    tr_warn("this is warning msg");
    tr_err("this is error msg");
    return 0;
}

