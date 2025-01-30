/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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

#include <stdint.h>

struct in6_addr;
struct iobuf_write;
struct iobuf_read;
struct timespec;

void dhcp_trace_rx(const void *buf, size_t buf_len, const struct in6_addr *src);
void dhcp_trace_tx(const void *buf, size_t buf_len, const struct in6_addr *dst);

int dhcp_get_option(const uint8_t *data, size_t len, uint16_t option, struct iobuf_read *option_payload);
void dhcp_fill_client_id(struct iobuf_write *buf, uint16_t hwaddr_type, const uint8_t *hwaddr);
void dhcp_fill_rapid_commit(struct iobuf_write *buf);
void dhcp_fill_identity_association(struct iobuf_write *buf, uint32_t ia_id, const uint8_t ipv6[16],
                                    uint32_t preferred_lifetime, uint32_t valid_lifetime);
void dhcp_fill_server_id(struct iobuf_write *buf, const uint8_t eui64[8]);
void dhcp_fill_elapsed_time(struct iobuf_write *buf, struct timespec *start);

int dhcp_get_client_hwaddr(const uint8_t *req, size_t req_len, const uint8_t **hwaddr);
uint32_t dhcp_get_identity_association_id(const uint8_t *req, size_t req_len);
int dhcp_get_random(int rt);

int dhcp_check_status_code(const uint8_t *req, size_t req_len);
int dhcp_check_rapid_commit(const uint8_t *req, size_t req_len);
int dhcp_check_elapsed_time(const uint8_t *req, size_t req_len);
int dhcp_check_server_id(const uint8_t *req, size_t req_len);
int dhcp_check_client_id(const uint8_t expected_eui64[8], const uint8_t *req, size_t req_len);

#endif /* DHCP_COMMON_H */
