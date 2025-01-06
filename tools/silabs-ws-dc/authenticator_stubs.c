/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <sys/uio.h>

#include "common/authenticator/authenticator_eap.h"
#include "common/authenticator/authenticator_radius.h"
#include "common/log.h"

/*
 * Silicon Labs Direct Connect requires a pre-installed Pairwise Master Key
 * (PMK), which implies to disable EAP support. To do so, stubs are provided to
 * replace authenticator_eap.c.
 */

struct tls_client_ctx;
struct tls_ctx;

void auth_eap_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp, const void *buf, size_t buf_len)
{
    TRACE(TR_DROP, "drop %-9s: EAP support disabled", "eap");
}

void auth_eap_send_request_identity(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    FATAL(3, "PMK mismatch");
}

void radius_send(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                 const void *buf, size_t buf_len)
{
    BUG();
}

void radius_init(struct auth_ctx *auth, const struct sockaddr *sa)
{
}

void tls_init(struct tls_ctx *tls, int endpoint, const struct iovec *ca_cert, const struct iovec *cert,
              const struct iovec *key)
{
}

void tls_init_client(struct tls_ctx *tls, struct tls_client_ctx *tls_client)
{
}
