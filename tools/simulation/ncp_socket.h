/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef NS3_NCP_SOCKET_H
#define NS3_NCP_SOCKET_H

void ncp_sk_open(const void *req, const void *req_data, void *cnf, void *cnf_data);
void ncp_sk_close(const void *req, const void *req_data, void *cnf, void *cnf_data);
void ncp_sk_bind(const void *req, const void *req_data, void *cnf, void *cnf_data);
void ncp_sk_send(const void *req, const void *req_data, void *cnf, void *cnf_data);
void ncp_sk_setopt(const void *_req, const void *req_data, void *_cnf, void *cnf_data);

#endif
