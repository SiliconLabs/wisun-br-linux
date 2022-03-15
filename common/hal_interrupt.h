/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef HAL_INTERRUPT_H
#define HAL_INTERRUPT_H

void platform_critical_init(void);
void platform_enter_critical(void);
void platform_exit_critical(void);

#endif
