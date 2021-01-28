/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_H
#define WSBR_H

#include <linux/if.h>

struct wsbr_ctxt {
    char dev_tun[IFNAMSIZ];
    int fd_tun;
    int fd_trig;
    int fd_bus;
};

#endif
