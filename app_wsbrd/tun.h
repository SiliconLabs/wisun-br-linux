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
#ifndef TUN_H
#define TUN_H
#include <stdint.h>

struct wsbr_ctxt;

void wsbr_tun_init(struct wsbr_ctxt *ctxt);
void wsbr_tun_read(struct wsbr_ctxt *ctxt);
int get_global_unicast_addr(char *if_name, uint8_t ip[static 16]);
ssize_t wsbr_tun_write(uint8_t *buf, uint16_t len);

#endif

