/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef OS_H
#define OS_H

struct slist;

struct os_ctxt {
    struct slist *timers;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct os_ctxt g_os_ctxt;

#endif
