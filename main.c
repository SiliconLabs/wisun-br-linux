/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include "hal_interrupt.h"

int main(int argc, char *argv[])
{
    platform_critical_init();
    printf("Hello World!\n");

    return 0;
}

