/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "slist.h"
#include "log.h"

unsigned int slist_len(struct slist **head)
{
    struct slist *it;
    int count = 0;

    BUG_ON(!head);

    for (it = *head; it != NULL; it = it->next)
        count++;

    return count;
}

void slist_push(struct slist **head, struct slist *item)
{
    BUG_ON(!head);
    BUG_ON(!item);
    BUG_ON(item->next);

    item->next = *head;
    *head = item;
}

void slist_push_back(struct slist **head, struct slist *item)
{
    struct slist **it = head;

    BUG_ON(!head);
    BUG_ON(!item);
    BUG_ON(item->next);

    while (it)
        it = &((*it)->next);
    *it = item;
}

struct slist *slist_pop(struct slist **head)
{
    struct slist *item;

    BUG_ON(!head);
    if (!*head)
        return NULL;
    item = *head;
    *head = item->next;
    item->next = NULL;

    return item;
}

void slist_insert(struct slist *item, struct slist *pos)
{
    BUG_ON(!item);
    BUG_ON(!pos);

    item->next = pos->next;
    pos->next = item;
}
