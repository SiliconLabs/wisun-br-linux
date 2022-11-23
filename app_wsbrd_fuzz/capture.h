/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef FUZZ_CAPTURE_H
#define FUZZ_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

struct fuzz_ctxt;

void fuzz_capture(struct fuzz_ctxt *ctxt, const void *data, size_t size);
void fuzz_capture_timers(struct fuzz_ctxt *ctxt);
void fuzz_capture_interface(struct fuzz_ctxt *ctxt, uint8_t interface,
                            const uint8_t src_addr[16], uint16_t src_port,
                            const void *data, size_t size);

#endif
