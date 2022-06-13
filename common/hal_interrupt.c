/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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


