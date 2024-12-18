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
#include "common/specs/ieee802159.h"
#include "common/specs/eapol.h"
#include "common/specs/eap.h"
#include "common/specs/ws.h"
#include "common/mbedtls_extra.h"
#include "common/mathutils.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/eap.h"

#include "supplicant.h"

#include "supplicant_eap.h"

static void supp_eap_send_response(struct supp_ctx *supp, uint8_t identifier, uint8_t type, struct pktbuf *buf)
{
    eap_write_hdr_head(buf, EAP_CODE_RESPONSE, identifier, type);
    eap_trace("tx-eap", pktbuf_head(buf), pktbuf_len(buf));
    eapol_write_hdr_head(buf, EAPOL_PACKET_TYPE_EAP);
    pktbuf_free(&supp->rt_buffer);
    pktbuf_push_tail(&supp->rt_buffer, pktbuf_head(buf), pktbuf_len(buf));
    supp_send_eapol(supp, IEEE802159_KMP_ID_8021X, buf);
    supp->last_tx_eap_type = type;
}

static void supp_eap_tls_send_response(struct supp_ctx *supp, const struct eap_hdr *eap_hdr)
{
    bool must_fragment = pktbuf_len(&supp->tls_io.tx) > WS_MTU_BYTES;
    uint32_t tx_len = pktbuf_len(&supp->tls_io.tx);
    struct pktbuf buf = { };
    uint8_t flags = 0;

    flags |= FIELD_PREP(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, must_fragment);
    if (!supp->fragment_id)
        flags |= FIELD_PREP(EAP_TLS_FLAGS_LENGTH_MASK, must_fragment);

    pktbuf_push_tail(&buf, NULL, MIN(pktbuf_len(&supp->tls_io.tx), WS_MTU_BYTES));
    pktbuf_pop_head(&supp->tls_io.tx, pktbuf_head(&buf),
                    MIN(pktbuf_len(&supp->tls_io.tx), WS_MTU_BYTES));

    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags))
        pktbuf_push_head_be32(&buf, tx_len);

    pktbuf_push_head_u8(&buf, flags);

    supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_TLS, &buf);
    pktbuf_free(&buf);
    supp->fragment_id++;
}

static void supp_eap_do_handshake(struct supp_ctx *supp, const struct eap_hdr *eap_hdr)
{
    struct pktbuf buf = { };
    int ret;

    pktbuf_free(&supp->tls_io.tx);
    supp->fragment_id = 0;

    ret = mbedtls_ssl_handshake(&supp->ssl_ctx);
    /*
     *   RFC5216 - 2.1.3. Termination
     * If the EAP server authenticates successfully, the peer MUST send an
     * EAP-Response packet of EAP-Type=EAP-TLS, and no data.  The EAP Server
     * then MUST respond with an EAP-Success message.
     */
    if (!ret) {
        pktbuf_push_tail_u8(&buf, 0); // eap-tls flags
        supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_TLS, &buf);
        pktbuf_free(&buf);
        return;
    }

    /*
     * Note: mbedtls sends a TLS alert message on error.
     *
     *   RFC5216 - 2.1.3. Termination
     * If the peer's authentication is unsuccessful, the EAP server SHOULD send
     * an EAP-Request packet with EAP-Type=EAP-TLS, encapsulating a TLS record
     * containing the appropriate TLS alert message.
     * To ensure that the peer receives the TLS alert message, the EAP server
     * MUST wait for the peer to reply with an EAP-Response packet.
     *
     * The peer MAY send an EAP-Response packet of EAP-Type=EAP-TLS containing a
     * TLS Alert message identifying the reason for the failed authentication.
     * To ensure that the EAP Server receives the TLS alert message, the peer
     * MUST wait for the EAP Server to reply before terminating the
     * conversation. The EAP Server MUST reply with an EAP-Failure packet since
     * server authentication failure is a terminal condition.
     */
    WARN_ON(ret != MBEDTLS_ERR_SSL_WANT_READ, "%s: mbedtls_ssl_handshake: %s", __func__, tr_mbedtls_err(ret));
    if (pktbuf_len(&supp->tls_io.tx) || ret != MBEDTLS_ERR_SSL_WANT_READ)
        supp_eap_tls_send_response(supp, eap_hdr);
}

static void supp_eap_tls_recv(struct supp_ctx *supp, const struct eap_hdr *eap_hdr, struct iobuf_read *iobuf)
{
    uint8_t flags = iobuf_pop_u8(iobuf);
    struct pktbuf buf = { };
    int remaining_size;

    if (iobuf->err) {
        TRACE(TR_DROP, "drop %-9s: invalid eap-tls request", "eap-tls");
        return;
    }

    /*
     *   RFC5216 - 2.1.1. Base Case
     * Once having received the peer's Identity, the EAP server MUST respond
     * with an EAP-TLS/Start packet, which is an EAP-Request packet with
     * EAP-Type=EAP-TLS, the Start (S) bit set, and no data.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_START_MASK, flags) && iobuf_remaining_size(iobuf)) {
        TRACE(TR_DROP, "drop %-9s: \"start\" bit is set but data is also present", "eap-tls");
        return;
    }
    if (!FIELD_GET(EAP_TLS_FLAGS_START_MASK, flags) && !supp->eap_tls_start_received) {
        TRACE(TR_DROP, "drop %-9s: \"start\" is not set when it should be", "eap-tls");
        return;
    }

    /*
     *   RFC5216 - 2.1.5. Fragmentation
     * The L flag is set to indicate the presence of the four-octet TLS
     * Message Length field, and MUST be set for the first fragment of a
     * fragmented TLS message or set of messages. The M flag is set on all
     * but the last fragment.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags) && supp->expected_rx_len) {
        TRACE(TR_DROP, "drop %-9s: \"length-included\" bit is set when it should not be", "eap-tls");
        return;
    }
    if (FIELD_GET(EAP_TLS_FLAGS_LENGTH_MASK, flags))
        supp->expected_rx_len = iobuf_pop_be32(iobuf);
    if (FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) && !supp->expected_rx_len) {
        TRACE(TR_DROP, "drop %-9s: \"more-fragments\" set without known length", "eap-tls");
        return;
    }

    remaining_size = iobuf_remaining_size(iobuf);

    if (supp->expected_rx_len && !FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) &&
        pktbuf_len(&supp->tls_io.rx) + remaining_size != supp->expected_rx_len) {
        TRACE(TR_DROP, "drop %-9s: invalid final fragment size", "eap-tls");
        return;
    }
    if (supp->expected_rx_len && FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags) &&
        pktbuf_len(&supp->tls_io.rx) + remaining_size >= supp->expected_rx_len) {
        TRACE(TR_DROP, "drop %-9s: \"more-fragments\" bit is set when it not should be", "eap-tls");
        return;
    }

    /*
     *   RFC5216 - 2.1.1. Base Case
     * The EAP-TLS conversation will then begin, with the peer sending an
     * EAP-Response packet with EAP-Type=EAP-TLS.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_START_MASK, flags) && !supp->eap_tls_start_received) {
        supp_eap_do_handshake(supp, eap_hdr);
        supp->eap_tls_start_received = true;
        return;
    }

    /*
     *   RFC5216 - 2.1.5. Fragmentation
     * Similarly, when the EAP server receives an EAP-Response with the M
     * bit set, it MUST respond with an EAP-Request with EAP-Type=EAP-TLS
     * and no data. The EAP peer MUST wait until it receives the EAP-Request
     * before sending another fragment.
     */
    if (!remaining_size) {
        supp_eap_tls_send_response(supp, eap_hdr);
        return;
    }

    pktbuf_push_tail(&supp->tls_io.rx, iobuf_pop_data_ptr(iobuf, remaining_size), remaining_size);

    /*
     *   RFC5216, 2.1.5 - Fragmentation
     * When an EAP-TLS peer receives an EAP-Request packet with the M bit
     * set, it MUST respond with an EAP-Response with EAP-Type=EAP-TLS and
     * no data. This serves as a fragment ACK.
     */
    if (FIELD_GET(EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK, flags)) {
        pktbuf_push_tail_u8(&buf, 0); // eap-tls flags
        supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_TLS, &buf);
        pktbuf_free(&buf);
        return;
    }

    supp_eap_do_handshake(supp, eap_hdr);
    supp->expected_rx_len = 0;
}

void supp_eap_tls_reset(struct supp_ctx *supp)
{
    supp->last_tx_eap_type = EAP_TYPE_NAK;
    supp->last_eap_identifier = -1;
    supp->eap_tls_start_received = false;
    pktbuf_init(&supp->tls_io.tx, NULL, 0);
    pktbuf_init(&supp->tls_io.rx, NULL, 0);
    pktbuf_init(&supp->rt_buffer, NULL, 0);
    supp->expected_rx_len = 0;
    supp->fragment_id = 0;
    mbedtls_ssl_session_reset(&supp->ssl_ctx);
}

/*
 *   RFC3748 - 5.2. Notification
 * The Notification Type is optionally used to convey a displayable
 * message from the authenticator to the peer.
 * [...]
 * The message MUST NOT be null terminated.
 */
static void supp_eap_notification_recv(struct iobuf_read *iobuf)
{
    TRACE(TR_SECURITY, "sec: notification=\"%.*s\"", iobuf_remaining_size(iobuf), (char *)iobuf_ptr(iobuf));
}

static void supp_eap_request_recv(struct supp_ctx *supp, const struct eap_hdr *eap_hdr, struct iobuf_read *iobuf)
{
    uint8_t type = iobuf_pop_u8(iobuf);
    struct pktbuf buf = { };

    if (iobuf->err) {
        TRACE(TR_DROP, "drop %-9s: invalid eap request", "eap");
        return;
    }

    /*
     *   RFC3748 - 4.1. Request and Response
     * If a peer receives a valid duplicate Request for which it has
     * already sent a Response, it MUST resend its original Response
     * without reprocessing the Request.
     */
    if (supp->last_eap_identifier == eap_hdr->identifier) {
        supp_send_eapol(supp, IEEE802159_KMP_ID_8021X, &supp->rt_buffer);
        return;
    }

    switch (type) {
    case EAP_TYPE_IDENTITY:
        if (supp->key_request_txalg.timer_rt.expire_ms)
            rfc8415_txalg_stop(&supp->key_request_txalg);
        // We are starting a new tls session so we reset eap-tls
        supp_eap_tls_reset(supp);
        // Wi-SUN does not specify to use any identity.
        // FreeRADIUS refuses an empty identity, so an aritrary value is used.
        pktbuf_push_tail(&buf, "Anonymous", strlen("Anonymous"));
        supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_IDENTITY, &buf);
        break;
    case EAP_TYPE_NOTIFICATION:
        supp_eap_notification_recv(iobuf);
        /*
         *   RFC3748 - 5.2. Notification
         * The peer MUST respond to a Notification Request with a Notification
         * Response unless the EAP authentication method specification prohibits
         * the use of Notification messages.
         */
        supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_NOTIFICATION, &buf);
        break;
    case EAP_TYPE_TLS:
        supp_eap_tls_recv(supp, eap_hdr, iobuf);
        break;
    default:
        /*
         *   RFC3748 - 2.1. Support for Sequences
         * A peer MUST NOT send a Nak (legacy or expanded) in reply to a Request
         * after an initial non-Nak Response has been sent.
         *
         *   RFC3748 - 5.3.1. Legacy Nak
         * Where a peer receives a Request for an unacceptable authentication
         * Type (4-253,255), or a peer lacking support for Expanded Types
         * receives a Request for Type 254, a Nak Response (Type 3) MUST be
         * sent.  The Type-Data field of the Nak Response (Type 3) MUST
         * contain one or more octets indicating the desired authentication
         * Type(s), one octet per Type, or the value zero (0) to indicate no
         * proposed alternative.
         */
        if (type > EAP_TYPE_NAK && supp->last_tx_eap_type == EAP_TYPE_NAK) {
            pktbuf_push_tail(&buf, (uint8_t[1]){ EAP_TYPE_TLS }, 1);
            supp_eap_send_response(supp, eap_hdr->identifier, EAP_TYPE_NAK, &buf);
        }
        else
            TRACE(TR_DROP, "drop %-9s: unsupported eap request type %d", "eap", type);
        break;
    }

    supp->last_eap_identifier = eap_hdr->identifier;
    pktbuf_free(&buf);
}

void supp_eap_recv(struct supp_ctx *supp, struct iobuf_read *iobuf)
{
    const struct eap_hdr *eap_hdr;

    eap_trace("rx-eap", iobuf_ptr(iobuf), iobuf_remaining_size(iobuf));

    eap_hdr = iobuf_pop_data_ptr(iobuf, sizeof(*eap_hdr));
    if (!eap_hdr) {
        TRACE(TR_DROP, "drop %-9s: invalid eap header", "eap");
        return;
    }

    switch (eap_hdr->code) {
    case EAP_CODE_REQUEST:
        supp_eap_request_recv(supp, eap_hdr, iobuf);
        timer_start_rel(NULL, &supp->failure_timer, supp->timeout_ms);
        break;
    case EAP_CODE_SUCCESS:
        supp_on_eap_success(supp);
        break;
    case EAP_CODE_FAILURE:
        /*
         *   RFC3748 - 4.2. Success and Failure
         * On the peer, after success result indications have been exchanged by
         * both sides, a Failure packet MUST be silently discarded.
         */
        if (mbedtls_ssl_is_handshake_over(&supp->ssl_ctx))
            break;
        /*
         *   IEEE 802.1X-2020, 8.8 Supplicant PAE counters
         * See "suppAuthFailWhileAuthenticating".
         *
         * Note: considering Wi-SUN adds the notion of EAPOL target, we
         * fallback to EAPOL Target selection.
         */
        timer_stop(NULL, &supp->failure_timer);
        supp->on_failure(supp);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported eap code %d", "eap", eap_hdr->code);
        break;
    }
}
