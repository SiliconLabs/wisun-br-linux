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
#include "common/authenticator/authenticator_key.h"
#include "common/specs/eap.h"
#include "common/specs/eapol.h"
#include "common/specs/ieee802159.h"
#include "common/specs/ws.h"
#include "common/mathutils.h"
#include "common/eap.h"
#include "common/endian.h"
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
    supp->eap_tls.frag_expected_len = 0;
    supp->eap_tls.frag_id = 0;
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

void auth_eap_send_success(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    struct pktbuf pktbuf = { };

    eap_write_hdr_head(&pktbuf, EAP_CODE_SUCCESS, supp->eap_id + 1, 0);
    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
    auth_eap_tls_reset_supp(supp); // free mbedtls buffers
    auth_key_pairwise_message_1_send(auth, supp);
}

void auth_eap_send_failure(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    struct pktbuf pktbuf = { };

    eap_write_hdr_head(&pktbuf, EAP_CODE_FAILURE, supp->eap_id + 1, 0);
    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
    auth_eap_tls_reset_supp(supp); // free mbedtls buffers
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

static void auth_eap_send_mbedtls(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    bool must_fragment = pktbuf_len(&supp->eap_tls.tls.io.tx) > WS_MTU_BYTES;
    uint32_t tx_len = pktbuf_len(&supp->eap_tls.tls.io.tx);
    struct pktbuf pktbuf = { };
    uint8_t flags = 0;

    flags |= FIELD_PREP(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, must_fragment);
    if (!supp->eap_tls.frag_id)
        flags |= FIELD_PREP(EAP_TLS_FLAGS_LENGTH_MASK, must_fragment);

    pktbuf_push_tail(&pktbuf, NULL, MIN(pktbuf_len(&supp->eap_tls.tls.io.tx), WS_MTU_BYTES));
    pktbuf_pop_head(&supp->eap_tls.tls.io.tx, pktbuf_head(&pktbuf),
                    MIN(pktbuf_len(&supp->eap_tls.tls.io.tx), WS_MTU_BYTES));

    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags))
        pktbuf_push_head_be32(&pktbuf, tx_len);

    pktbuf_push_head_u8(&pktbuf, flags);

    auth_eap_send_tls(auth, supp, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    pktbuf_free(&pktbuf);
    supp->eap_tls.frag_id++;
}

static void auth_eap_handshake(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    pktbuf_free(&supp->eap_tls.tls.io.tx);
    supp->eap_tls.frag_id = 0;
    supp->eap_tls.last_mbedtls_status = mbedtls_ssl_handshake(&supp->eap_tls.tls.ssl_ctx);

    if (supp->eap_tls.last_mbedtls_status && supp->eap_tls.last_mbedtls_status != MBEDTLS_ERR_SSL_WANT_READ) {
        WARN("%s: mbedtls_ssl_handshake: %d", __func__, supp->eap_tls.last_mbedtls_status);
        /*
         * If there's an error but no TLS alert message to send, we directly
         * send an EAP-Failure.
         */
        if (!pktbuf_len(&supp->eap_tls.tls.io.tx)) {
            auth_eap_send_failure(auth, supp);
            return;
        }
    }
    auth_eap_send_mbedtls(auth, supp);
}

static void auth_eap_recv_resp_tls(struct auth_ctx *auth, struct auth_supp_ctx *supp, struct iobuf_read *iobuf)
{
    uint8_t flags = iobuf_pop_u8(iobuf);
    uint8_t tx_flags = 0;
    int remaining_size;

    if (iobuf->err) {
        TRACE(TR_DROP, "drop %-9s: invalid response", "eap-tls");
        return;
    }

    /*
     *   RFC5216 - 2.1.5. Fragmentation
     * The L flag is set to indicate the presence of the four-octet TLS
     * Message Length field, and MUST be set for the first fragment of a
     * fragmented TLS message or set of messages. The M flag is set on all
     * but the last fragment.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags) && supp->eap_tls.frag_expected_len) {
        TRACE(TR_DROP, "drop %-9s: \"length-included\" bit is set when it should not be", "eap-tls");
        return;
    }
    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags)) {
        supp->eap_tls.frag_expected_len = iobuf_pop_be32(iobuf);
        if (iobuf->err) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "eap-tls");
            return;
        }
    }
    if (FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) && !supp->eap_tls.frag_expected_len) {
        TRACE(TR_DROP, "drop %-9s: \"more-fragments\" set without known length", "eap-tls");
        return;
    }

    remaining_size = iobuf_remaining_size(iobuf);

    if (supp->eap_tls.frag_expected_len && !FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) &&
        pktbuf_len(&supp->eap_tls.tls.io.rx) + remaining_size != supp->eap_tls.frag_expected_len) {
        TRACE(TR_DROP, "drop %-9s: invalid final fragment size", "eap-tls");
        return;
    }
    if (supp->eap_tls.frag_expected_len && FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) &&
        pktbuf_len(&supp->eap_tls.tls.io.rx) + remaining_size >= supp->eap_tls.frag_expected_len) {
        TRACE(TR_DROP, "drop %-9s: \"more-fragments\" bit is set when it not should be", "eap-tls");
        return;
    }

    /*
     *   RFC5216 - 2.1.3. Termination
     * To ensure that the peer receives the TLS alert message, the EAP
     * server MUST wait for the peer to reply with an EAP-Response packet.
     * The EAP-Response packet sent by the peer MAY encapsulate a TLS
     * client_hello handshake message, in which case the EAP server MAY
     * allow the EAP-TLS conversation to be restarted, or it MAY contain an
     * EAP-Response packet with EAP-Type=EAP-TLS and no data, in which case
     * the EAP-Server MUST send an EAP-Failure packet and terminate the
     * conversation.
     * [...]
     * If the EAP server authenticates successfully, the peer MUST send an
     * EAP-Response packet of EAP-Type=EAP-TLS, and no data. The EAP Server
     * then MUST respond with an EAP-Success message.
     *
     *   RFC5216 - 2.1.5. Fragmentation
     * When an EAP-TLS peer receives an EAP-Request packet with the M bit
     * set, it MUST respond with an EAP-Response with EAP-Type=EAP-TLS and
     * no data. This serves as a fragment ACK. The EAP server MUST wait
     * until it receives the EAP-Response before sending another fragment.
     */
    if (!remaining_size) {
        if (!supp->eap_tls.last_mbedtls_status)
            auth_eap_send_success(auth, supp);
        else if (supp->eap_tls.last_mbedtls_status != MBEDTLS_ERR_SSL_WANT_READ)
            auth_eap_send_failure(auth, supp);
        else
            auth_eap_send_mbedtls(auth, supp);
        return;
    }

    pktbuf_push_tail(&supp->eap_tls.tls.io.rx, iobuf_pop_data_ptr(iobuf, remaining_size), remaining_size);

    /*
     *   RFC5216, 2.1.5 - Fragmentation
     * Similarly, when the EAP server receives an EAP-Response with the M
     * bit set, it MUST respond with an EAP-Request with EAP-Type=EAP-TLS
     * and no data. This serves as a fragment ACK. The EAP peer MUST wait
     * until it receives the EAP-Request before sending another fragment.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags)) {
        auth_eap_send_tls(auth, supp, &tx_flags, sizeof(tx_flags));
        return;
    }

    auth_eap_handshake(auth, supp);
    supp->eap_tls.frag_expected_len = 0;
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
    case EAP_TYPE_TLS:
        auth_eap_recv_resp_tls(auth, supp, iobuf);
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
    if (be16toh(eap->length) > buf_len) {
        TRACE(TR_DROP, "drop %-9s: invalid packet length", "eap");
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
