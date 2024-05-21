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
#ifndef DHCP_COMMON_H
#define DHCP_COMMON_H

struct iobuf_write;
struct iobuf_read;

int dhcp_get_option(const uint8_t *data, size_t len, uint16_t option, struct iobuf_read *option_payload);
void dhcp_fill_client_id(struct iobuf_write *buf, uint16_t hwaddr_type, const uint8_t *hwaddr);
void dhcp_fill_rapid_commit(struct iobuf_write *buf);

#endif /* DHCP_COMMON_H */
