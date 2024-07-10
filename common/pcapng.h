/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef PCAPNG_H
#define PCAPNG_H
#include <stdint.h>

/*
 * The pcapng format is specified in draft-tuexen-opsawg-pcapng
 * https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng-05
 * Only features required by the Wi-SUN TBU are implemented.
 */

// Link types defined in draft-richardson-opsawg-pcaplinktype
// https://datatracker.ietf.org/doc/html/draft-richardson-opsawg-pcaplinktype-00
#define LINKTYPE_IEEE802_15_4_NOFCS 230

struct iobuf_write;

void pcapng_write_shb(struct iobuf_write *buf);
void pcapng_write_idb(struct iobuf_write *buf, uint16_t link_type);
void pcapng_write_epb(struct iobuf_write *buf,
                      uint64_t timestamp_us,
                      const void *pkt, size_t pkt_len);

#endif
