/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <pthread.h>

#include "hal_interrupt.h"

// NOTE: this mutex is probably useless
static pthread_mutex_t irqsym_lock;

void platform_critical_init(void)
{
    pthread_mutexattr_t attr;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&irqsym_lock, &attr);
}

void platform_enter_critical(void)
{
    pthread_mutex_lock(&irqsym_lock);
}

void platform_exit_critical(void)
{
    pthread_mutex_unlock(&irqsym_lock);
}


