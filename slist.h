/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
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
