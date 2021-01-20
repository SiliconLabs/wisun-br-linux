/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <pthread.h>

static pthread_mutex_t irqsym_lock;

int main(int argc, char *argv[])
{
    printf("Hello World!\n");

    return 0;
}

void platform_critical_init(void)
{
    pthread_mutex_init(&irqsym_lock, NULL);
}

void platform_enter_critical(void)
{
    pthread_mutex_lock(&irqsym_lock);
}

void platform_exit_critical(void)
{
    pthread_mutex_unlock(&irqsym_lock);
}

