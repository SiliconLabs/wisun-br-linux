/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSMAC_H
#define WSMAC_H

struct wsmac_ctxt {
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsmac_ctxt g_ctxt;

#endif
