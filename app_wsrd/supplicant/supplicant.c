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
#define _DEFAULT_SOURCE
#include <endian.h>
#include <stddef.h>

#include <mbedtls/sha256.h>
#include <mbedtls/debug.h>

#include "common/specs/ieee802159.h"
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/specs/eap.h"
#include "common/specs/ws.h"
#include "common/crypto/ieee80211.h"
#include "common/crypto/ws_keys.h"
#include "common/ieee802154_frame.h"
#include "common/mbedtls_extra.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/kde.h"

#include "supplicant_eap.h"
#include "supplicant_key.h"

#include "supplicant.h"

void supp_send_eapol(struct supp_ctx *supp, uint8_t kmp_id, const void *buf, size_t buf_len)
{
    uint8_t *dst = supp->get_target(supp);
    const struct eapol_hdr *hdr;

    BUG_ON(buf_len < sizeof(*hdr));
    hdr = buf;

    if (!memcmp(dst, &ieee802154_addr_bc, 8)) {
        TRACE(TR_DROP, "drop %-9s: no eapol target available", "eapol");
        return;
    }

    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%u", "tx-eapol",
          val_to_str(hdr->packet_type, eapol_frames, "[UNK]"), be16toh(hdr->packet_body_length));
    supp->sendto_mac(supp, kmp_id, buf, buf_len, dst);
}

static void supp_failure_key_request(struct rfc8415_txalg *txalg)
{
    struct supp_ctx *supp = container_of(txalg, struct supp_ctx, key_request_txalg);

    TRACE(TR_SECURITY, "sec: no valid response to key request after %d retries", supp->key_request_txalg.mrc);
    supp->on_failure(supp);
}

static void supp_timeout_key_request(struct rfc8415_txalg *txalg)
{
    struct supp_ctx *supp = container_of(txalg, struct supp_ctx, key_request_txalg);
    struct eapol_key_frame frame = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_REQ, true)),
        .replay_counter = htobe64(supp->tls_client.pmk.replay_counter),
    };
    struct pktbuf buf = { };
    uint8_t pmkid[16];
    uint8_t ptkid[16];
    uint8_t lgtkl = 0;
    uint8_t gtkl = 0;
    int i;

    ieee80211_derive_pmkid(supp->tls_client.pmk.key, supp->authenticator_eui64, supp->eui64, pmkid);
    ws_derive_ptkid(supp->ptk, supp->authenticator_eui64, supp->eui64, ptkid);

    for (i = 0; i < WS_GTK_COUNT; i++)
        if (!timer_stopped(&supp->gtks[i].expiration_timer))
            gtkl |= BIT(i);
    for (; i < ARRAY_SIZE(supp->gtks); i++)
        if (!timer_stopped(&supp->gtks[i].expiration_timer))
            lgtkl |= BIT(i - WS_GTK_COUNT);

    if (memzcmp(supp->tls_client.pmk.key, sizeof(supp->tls_client.pmk)))
        kde_write_pmkid(&buf, pmkid);
    if (memzcmp(supp->ptk, sizeof(supp->ptk)))
        kde_write_ptkid(&buf, ptkid);
    kde_write_gtkl(&buf, gtkl);
    kde_write_lgtkl(&buf, lgtkl);
    kde_write_nr(&buf, WS_NR_ROLE_ROUTER);
    frame.data_length = htobe16(pktbuf_len(&buf));
    pktbuf_push_head(&buf, &frame, sizeof(frame));
    eapol_write_hdr_head(&buf, EAPOL_PACKET_TYPE_KEY);
    supp_send_eapol(supp, IEEE802159_KMP_ID_8021X, pktbuf_head(&buf), pktbuf_len(&buf));
    pktbuf_free(&buf);
}

void supp_on_eap_success(struct supp_ctx *supp)
{
    // Wait for 4-Way Handshake message 1
    timer_start_rel(NULL, &supp->failure_timer, supp->timeout_ms);
}

static void supp_failure_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct supp_ctx *supp = container_of(timer, struct supp_ctx, failure_timer);

    /*
     *   IEEE 802.1X-2020, 8.8 Supplicant PAE counters
     * See "suppAuthTimeoutsWhileAuthenticating".
     *
     * Note: considering Wi-SUN adds the notion of EAPOL target, we consider a
     * such timeout as a failure and fallback to EAPOL Target selection.
     */
    TRACE(TR_SECURITY, "sec: next eapol packet timeout");
    supp->on_failure(supp);
}

void supp_recv_eapol(struct supp_ctx *supp, uint8_t kmp_id, const uint8_t *buf, size_t buf_len,
                     const uint8_t authenticator_eui64[8])
{
    const struct eapol_hdr *eapol_hdr;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    if (!supp->running) {
        TRACE(TR_DROP, "drop %-9s: supplicant not runnning", "eapol");
        return;
    }

    eapol_hdr = iobuf_pop_data_ptr(&iobuf, sizeof(*eapol_hdr));
    if (!eapol_hdr) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol header", "eapol");
        return;
    }
    if (eapol_hdr->protocol_version != EAPOL_PROTOCOL_VERSION) {
        TRACE(TR_DROP, "drop %-9s: unsupported eapol protocol version %d", "eapol", eapol_hdr->protocol_version);
        return;
    }

    if ((kmp_id == IEEE802159_KMP_ID_8021X && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_EAP) ||
        (kmp_id == IEEE802159_KMP_ID_80211_4WH && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_KEY) ||
        (kmp_id == IEEE802159_KMP_ID_80211_GKH && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_KEY)) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet type %s for KMP ID %d", "eapol",
              val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), kmp_id);
        return;
    }

    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%d", "rx-eapol",
          val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), ntohs(eapol_hdr->packet_body_length));

    if (authenticator_eui64)
        memcpy(supp->authenticator_eui64, authenticator_eui64, sizeof(supp->authenticator_eui64));

    /*
     *   RFC3748 - 4.2. Success and Failure
     * Because the Success and Failure packets are not
     * acknowledged, they are not retransmitted by the authenticator, and
     * may be potentially lost. A peer MUST allow for this circumstance as
     * described in this note.
     */
    if (mbedtls_ssl_is_handshake_over(&supp->tls_client.ssl_ctx) &&
        eapol_hdr->packet_type != EAPOL_PACKET_TYPE_EAP && !timer_stopped(&supp->failure_timer))
        supp_on_eap_success(supp);

    switch (eapol_hdr->packet_type) {
    case EAPOL_PACKET_TYPE_EAP:
        supp_eap_recv(supp, &iobuf);
        break;
    case EAPOL_PACKET_TYPE_KEY:
        supp_key_recv(supp, &iobuf);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported eapol packet type %d", "eapol", eapol_hdr->packet_type);
        break;
    }
}

/*
 *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.5 FFN Join State 5: Operational
 * A previously installed GTK[X] expires. At the expiry time, the GTK is
 * removed both from the Border Router and PAN FFNs (all setting their local
 * hash value to 0).
 */
static void supp_gtk_expiration_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct supp_ctx *supp = container_of(group, struct supp_ctx, timer_group);
    struct ws_gtk *gtk = container_of(timer, struct ws_gtk, expiration_timer);
    const int slot = (int)(gtk - supp->gtks);

    TRACE(TR_SECURITY, "sec: %s expired", tr_gtkname(slot));
    supp->on_gtk_change(supp, NULL, slot + 1);
    memset(gtk->key, 0, sizeof(gtk->key));
}

bool supp_gtkhash_mismatch(struct supp_ctx *supp, const uint8_t gtkhash[8], uint8_t gtkhash_index)
{
    uint8_t hash[32] = { };
    bool mismatch;

    if (!supp->running)
        return true;

    if (timer_stopped(&supp->gtks[gtkhash_index - 1].expiration_timer)) {
        mismatch = memzcmp(gtkhash, 8);
    } else {
        xmbedtls_sha256(supp->gtks[gtkhash_index - 1].key, 16, hash, 0);
        mismatch = memcmp(hash + 24, gtkhash, 8);
    }
    if (mismatch)
        TRACE(TR_SECURITY, "sec: gtkhash[%u] mismatch got:%s expected:%s", gtkhash_index,
              tr_key(hash + 24, 8), tr_key(gtkhash, 8));
    return mismatch;
}

void supp_start_key_request(struct supp_ctx *supp)
{
    if (!rfc8415_txalg_stopped(&supp->key_request_txalg) || !timer_stopped(&supp->failure_timer))
        return;
    rfc8415_txalg_start(&supp->key_request_txalg);
    supp->running = true;
    TRACE(TR_SECURITY, "sec: %-8s tx=%"PRIu64"ms", "eapol-key",
          timer_duration_ms(&supp->key_request_txalg.timer_delay));
}

void supp_reset(struct supp_ctx *supp)
{
    supp->running = false;
    rfc8415_txalg_stop(&supp->key_request_txalg);
    timer_stop(NULL, &supp->failure_timer);
    supp_eap_tls_reset(supp);
}

void supp_init(struct supp_ctx *supp, struct iovec *ca_cert, struct iovec *cert, struct iovec *key,
               const uint8_t eui64[8])
{
    BUG_ON(!supp->sendto_mac);
    BUG_ON(!supp->get_target);
    BUG_ON(!supp->on_gtk_change);
    BUG_ON(!supp->on_failure);

    timer_group_init(&supp->timer_group);
    supp->failure_timer.callback = supp_failure_timer_timeout;
    supp->key_request_txalg.tx = supp_timeout_key_request;
    supp->key_request_txalg.fail = supp_failure_key_request;
    for (int i = 0; i < ARRAY_SIZE(supp->gtks); i++)
        supp->gtks[i].expiration_timer.callback = supp_gtk_expiration_timer_timeout;
    rfc8415_txalg_init(&supp->key_request_txalg);
    memcpy(supp->eui64, eui64, sizeof(supp->eui64));

    tls_init(&supp->tls, MBEDTLS_SSL_IS_CLIENT, ca_cert, cert, key);
    tls_init_client(&supp->tls, &supp->tls_client);
}
