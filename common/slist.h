/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SLIST_H
#define SLIST_H

#include "utils.h"

struct slist {
    struct slist *next;
};

#define SLIST_FOR_EACH(head, it) \
    for ((it) = (head); (it) != NULL; (it) = (it)->next)

#define SLIST_FOR_EACH_ENTRY(head, entry, member) \
    for ((entry) = container_of(head, typeof(*entry), member); \
         (entry) != container_of(NULL, typeof(*entry), member);     \
         (entry) = container_of((entry)->member.next, typeof(*entry), member))

#define SLIST_REMOVE(head, entry, member, cond) \
    ({                                                                 \
        struct slist **__prev = &head;                                 \
                                                                       \
        entry = NULL;                                                  \
        if (*__prev) {                                                 \
            entry = container_of(*__prev, typeof(*entry), member);     \
            while (!(cond) && entry->member.next) {                    \
                __prev = &entry->member.next;                          \
                entry = container_of(*__prev, typeof(*entry), member); \
            }                                                          \
            if (cond) {                                                \
                *__prev = entry->member.next;                          \
                entry->member.next = NULL;                             \
            }                                                          \
        }                                                              \
        entry;                                                         \
    })


unsigned int slist_len(struct slist **head);
void slist_push(struct slist **head, struct slist *item);
void slist_push_back(struct slist **head, struct slist *item);
struct slist *slist_pop(struct slist **head);
void slist_insert(struct slist *item, struct slist *pos);

#endif
