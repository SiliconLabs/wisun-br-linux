/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_random.h"

#ifdef RANDLIB_PRNG

void arm_random_module_init(void)
{
}

uint32_t arm_random_seed_get(void)
{
    return 0;
}

#endif
