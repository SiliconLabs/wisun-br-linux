/*
 * Copyright (c) 2014-2019 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <string.h>
#include "nsdynmemLIB.h"
#include "platform/arm_hal_interrupt.h"
#include <stdlib.h>
#include "ns_list.h"

static ns_mem_book_t *default_book; // heap pointer for original "ns_" API use
typedef int ns_mem_word_size_t; // internal signed heap block size type


void ns_dyn_mem_init(void *heap, ns_mem_heap_size_t h_size,
                     void (*passed_fptr)(heap_fail_t), mem_stat_t *info_ptr)
{
    default_book = ns_mem_init(heap, h_size, passed_fptr, info_ptr);
}

int ns_dyn_mem_region_add(void *region_ptr, ns_mem_heap_size_t region_size)
{
    return ns_mem_region_add(default_book, region_ptr, region_size);
}

const mem_stat_t *ns_dyn_mem_get_mem_stat(void)
{
    return NULL;
}

ns_mem_book_t *ns_mem_init(void *heap, ns_mem_heap_size_t h_size,
                           void (*passed_fptr)(heap_fail_t),
                           mem_stat_t *info_ptr)
{
    return NULL;
}

int ns_mem_region_add(ns_mem_book_t *book, void *region_ptr, ns_mem_heap_size_t region_size)
{
    (void) book;
    (void) region_ptr;
    (void) region_size;

    return -1;
}

const mem_stat_t *ns_mem_get_mem_stat(ns_mem_book_t *heap)
{
    return NULL;
}

int ns_mem_set_temporary_alloc_free_heap_threshold(ns_mem_book_t *book, uint8_t free_heap_percentage, ns_mem_heap_size_t free_heap_amount)
{
    return -3;
}

extern int ns_dyn_mem_set_temporary_alloc_free_heap_threshold(uint8_t free_heap_percentage, ns_mem_heap_size_t free_heap_amount)
{
    return ns_mem_set_temporary_alloc_free_heap_threshold(default_book, free_heap_percentage, free_heap_amount);
}


// For direction, use 1 for direction up and -1 for down
static void *ns_mem_internal_alloc(ns_mem_book_t *book, const ns_mem_block_size_t alloc_size, int direction)
{
    void *retval = NULL;
    if (alloc_size) {
        platform_enter_critical();
        retval = malloc(alloc_size);
        platform_exit_critical();
    }
    return retval;
}

void *ns_mem_alloc(ns_mem_book_t *heap, ns_mem_block_size_t alloc_size)
{
    return ns_mem_internal_alloc(heap, alloc_size, -1);
}

void *ns_mem_temporary_alloc(ns_mem_book_t *heap, ns_mem_block_size_t alloc_size)
{
    return ns_mem_internal_alloc(heap, alloc_size, 1);
}

void *ns_dyn_mem_alloc(ns_mem_block_size_t alloc_size)
{
    return ns_mem_alloc(default_book, alloc_size);
}

void *ns_dyn_mem_temporary_alloc(ns_mem_block_size_t alloc_size)
{
    return ns_mem_temporary_alloc(default_book, alloc_size);
}



void ns_mem_free(ns_mem_book_t *book, void *block)
{
    platform_enter_critical();
    free(block);
    platform_exit_critical();
}

void ns_dyn_mem_free(void *block)
{
    ns_mem_free(default_book, block);
}
