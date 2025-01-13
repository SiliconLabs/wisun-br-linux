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
#include "common/authenticator/authenticator.h"
#include "common/authenticator/authenticator_radius.h"
#include "common/specs/eap.h"
#include "common/specs/eapol.h"
#include "common/specs/ieee802159.h"
#include "common/eap.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/log.h"

#include "authenticator_eap.h"

void auth_eap_send(struct auth_ctx *auth, struct auth_supp_ctx *supp, struct pktbuf *pktbuf)
{
    struct eap_hdr eap;

    eap_trace("tx-eap", pktbuf_head(pktbuf), pktbuf_len(pktbuf));

    BUG_ON(pktbuf_len(pktbuf) < sizeof(eap));
    eap = *(const struct eap_hdr *)pktbuf_head(pktbuf);
    supp->eap_id = eap.identifier;

    eapol_write_hdr_head(pktbuf, EAPOL_PACKET_TYPE_EAP);
    auth_send_eapol(auth, supp, IEEE802159_KMP_ID_8021X,
                    pktbuf_head(pktbuf), pktbuf_len(pktbuf));

    /*
     *   RFC 3748 4.2. Success and Failure
     * Because the Success and Failure packets are not acknowledged, they are
     * not retransmitted by the authenticator, and may be potentially lost.
     */
    if (eap.code != EAP_CODE_SUCCESS && eap.code != EAP_CODE_FAILURE)
        auth_rt_timer_start(auth, supp, IEEE802159_KMP_ID_8021X,
                            pktbuf_head(pktbuf), pktbuf_len(pktbuf));
}

static void auth_eap_tls_reset_supp(struct auth_supp_ctx *supp)
{
    pktbuf_init(&supp->eap_tls.tls.io.tx, NULL, 0);
    pktbuf_init(&supp->eap_tls.tls.io.rx, NULL, 0);
    supp->eap_id = 0;
    mbedtls_ssl_session_reset(&supp->eap_tls.tls.ssl_ctx);
}

void auth_eap_send_request_identity(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    struct pktbuf pktbuf = { };

    auth_eap_tls_reset_supp(supp);
    eap_write_hdr_head(&pktbuf, EAP_CODE_REQUEST, supp->eap_id + 1, EAP_TYPE_IDENTITY);
    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
}

void auth_eap_send_failure(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    struct pktbuf pktbuf = { };

    eap_write_hdr_head(&pktbuf, EAP_CODE_FAILURE, supp->eap_id + 1, 0);
    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
}

static void auth_eap_send_tls(struct auth_ctx *auth, struct auth_supp_ctx *supp, const void *buf, size_t buf_len)
{
    struct pktbuf pktbuf = { };

    pktbuf_push_tail(&pktbuf, buf, buf_len);
    eap_write_hdr_head(&pktbuf, EAP_CODE_REQUEST, supp->eap_id + 1, EAP_TYPE_TLS);
    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
}

static void auth_eap_send_tls_start(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    uint8_t flags = FIELD_PREP(EAP_TLS_FLAGS_START_MASK, 1);

    auth_eap_send_tls(auth, supp, &flags, sizeof(flags));
}

static void auth_eap_recv_resp_nak(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    /*
     *   RFC 3748 5.3. Nak
     * The legacy Nak Type is valid only in Response messages. It is sent in
     * reply to a Request where the desired authentication Type is
     * unacceptable.
     *
     * This implementation only supports the TLS authentication type,
     * therefore we send an EAP-Failure directly.
     */
    TRACE(TR_SECURITY, "sec: TLS authentication type unsupported by peer");
    auth_eap_send_failure(auth, supp);
}

static void auth_eap_recv_resp_identity(struct auth_ctx *auth, struct auth_supp_ctx *supp, struct iobuf_read *iobuf)
{
    TRACE(TR_SECURITY, "sec: identity=\"%.*s\"", iobuf_remaining_size(iobuf), (char *)iobuf_ptr(iobuf));

    /*
     *   RFC5216 - 2.1.1. Base Case
     * The EAP-TLS conversation will then begin, with the peer sending an
     * EAP-Response packet with EAP-Type=EAP-TLS.
     */
    auth_eap_send_tls_start(auth, supp);
}

static void auth_eap_recv_resp(struct auth_ctx *auth, struct auth_supp_ctx *supp, struct iobuf_read *iobuf)
{
    uint8_t type = iobuf_pop_u8(iobuf);

    if (iobuf->err) {
        TRACE(TR_DROP, "drop %-9s: invalid eap response", "eap");
        return;
    }

    switch (type) {
    case EAP_TYPE_IDENTITY:
        auth_eap_recv_resp_identity(auth, supp, iobuf);
        break;
    case EAP_TYPE_NAK:
        auth_eap_recv_resp_nak(auth, supp);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported type", "eap");
        break;
    }
}

void auth_eap_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp, const void *buf, size_t buf_len)
{
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };
    const struct eap_hdr *eap;

    eap = iobuf_pop_data_ptr(&iobuf, sizeof(struct eap_hdr));
    if (!eap) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "eap");
        return;
    }

    eap_trace("rx-eap", buf, buf_len);
    eap = buf;
    if (eap->identifier != supp->eap_id) {
        TRACE(TR_DROP, "drop %-9s: invalid identifier", "eap");
        return;
    }

    timer_stop(&auth->timer_group, &supp->rt_timer);

    if (auth->radius_fd >= 0)
        return radius_send_eap(auth, supp, buf, buf_len);

    switch (eap->code) {
    case EAP_CODE_RESPONSE:
        auth_eap_recv_resp(auth, supp, &iobuf);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported eap code %d", "eap", eap->code);
        break;
    }
}
