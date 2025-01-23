/*
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
#include <errno.h>
#include <inttypes.h>

#include "common/specs/ieee802159.h"
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/crypto/ieee80211.h"
#include "common/crypto/hmac_md.h"
#include "common/crypto/nist_kw.h"
#include "common/crypto/ws_keys.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/kde.h"
#include "common/log.h"

#include "supplicant.h"

#include "supplicant_key.h"

static void supp_key_message_send(struct supp_ctx *supp, struct eapol_key_frame *response)
{
    struct pktbuf buf = { };
    const uint8_t *ptk;
    uint8_t kmp_id;

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * [...] the EAPOL Key MIC is a MIC of the EAPOL-Key frames, from and
     * including the EAPOL protocol version field to and including the Key Data
     * field, calculated with the Key MIC field set to 0.
     */
    pktbuf_push_tail(&buf, response, sizeof(*response));
    eapol_write_hdr_head(&buf, EAPOL_PACKET_TYPE_KEY);

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(response->information)) == IEEE80211_KEY_TYPE_PAIRWISE) {
        ptk = supp->tls_client.ptk.tkey;
        kmp_id = IEEE802159_KMP_ID_80211_4WH;
    } else {
        ptk = supp->tls_client.ptk.key;
        kmp_id = IEEE802159_KMP_ID_80211_GKH;
    }

    /*
     *   IEEE 802.11-2020, 12.7.6 4-way handshake
     * MIC(KCK, EAPOL)
     */
    hmac_md_sha1(ieee80211_kck(ptk), IEEE80211_AKM_1_KCK_LEN_BYTES,
                 pktbuf_head(&buf), pktbuf_len(&buf),
                 response->mic, sizeof(response->mic));

    // Update MIC
    pktbuf_pop_tail(&buf, NULL, sizeof(*response));
    pktbuf_push_tail(&buf, response, sizeof(*response));
    supp_send_eapol(supp, kmp_id, pktbuf_head(&buf), pktbuf_len(&buf));
    pktbuf_free(&buf);
}

static void supp_key_group_message_2_send(struct supp_ctx *supp)
{
    struct eapol_key_frame message = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1)),
        .replay_counter = htobe64(supp->tls_client.pmk.replay_counter),
    };

    TRACE(TR_SECURITY, "sec: %-8s msg=2", "tx-gkh");
    supp_key_message_send(supp, &message);
}

static void supp_key_pairwise_message_4_send(struct supp_ctx *supp)
{
    struct eapol_key_frame response = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_PAIRWISE) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1)),
        .replay_counter = htobe64(supp->tls_client.pmk.replay_counter),
    };

    TRACE(TR_SECURITY, "sec: %-8s msg=4", "tx-4wh");
    supp_key_message_send(supp, &response);
}

static void supp_key_pairwise_message_2_send(struct supp_ctx *supp, const struct eapol_key_frame *request)
{
    struct eapol_key_frame response = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_PAIRWISE) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1)),
        /*
         * Considering we do not update the local replay counter from message 1,
         * we have to use the one in the request.
         */
        .replay_counter = request->replay_counter,
    };

    memcpy(response.nonce, supp->snonce, sizeof(supp->snonce));
    TRACE(TR_SECURITY, "sec: %-8s msg=2", "tx-4wh");
    supp_key_message_send(supp, &response);
}

static bool supp_key_is_mic_valid(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                  struct iobuf_read *iobuf)
{
    const uint8_t *ptk;

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tls_client.ptk.tkey;
    else
        ptk = supp->tls_client.ptk.key;

    if (!ieee80211_is_mic_valid(ptk, frame, iobuf_ptr(iobuf), iobuf_remaining_size(iobuf)))
        return false;

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * The local Key Replay Counter field should not be updated until after the
     * EAPOL-Key MIC is checked and is found to be valid.
     */
    supp->tls_client.pmk.replay_counter = be64toh(frame->replay_counter);
    return true;
}

static int supp_key_install_gtk(struct supp_ctx *supp, const struct kde_gtk *gtk_kde, uint32_t lifetime_kde, bool is_lgtk)
{
    const uint8_t count = is_lgtk ? WS_LGTK_COUNT : WS_GTK_COUNT;
    const uint8_t offset = is_lgtk ? WS_GTK_COUNT : 0;
    uint8_t key_id, key_index;

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.2.4 Group Transient Key KDE (GTK)
     * The TX field MUST be set to 0 and ignored upon reception.
     */
    if (gtk_kde->flags & KDE_GTK_MASK_TX)
        TRACE(TR_IGNORE, "ignore: unsupported GTK KDE tx bit");

    key_id = FIELD_GET(KDE_GTK_MASK_KEY_ID, gtk_kde->flags);
    if (key_id > count) {
        TRACE(TR_DROP, "drop %-9s: invalid key-id=%u", "eapol-key", key_id);
        return -EINVAL;
    }
    key_index = key_id + 1 + offset;

    /*
     *   IEEE 802.11-2020, 12.7.7.4 Group key handshake implementation considerations
     * To prevent key reinstallation attacks, the Supplicant shall maintain a
     * copy of the most recent GTK [...] The Supplicant shall not install a GTK
     * [...] when the key to be set matches either of these two keys (see 6.3.19).
     */
    for (int i = offset; i < offset + count; i++) {
        if (!memcmp(supp->gtks[i].key, gtk_kde->gtk, sizeof(gtk_kde->gtk)) && i != key_index - 1) {
            TRACE(TR_DROP, "drop %-9s: key reinstallation detected at index %d", "eapol-key", i);
            return -EPERM;
        }
    }

    // Prevent Key Reinstallation Attacks (https://www.krackattacks.com)
    if (memcmp(supp->gtks[key_index - 1].key, gtk_kde->gtk, sizeof(gtk_kde->gtk))) {
        memcpy(supp->gtks[key_index - 1].key, gtk_kde->gtk, sizeof(gtk_kde->gtk));
        timer_start_rel(&supp->timer_group, &supp->gtks[key_index - 1].expiration_timer, lifetime_kde * 1000);
        supp->on_gtk_change(supp, gtk_kde->gtk, key_index);
        TRACE(TR_SECURITY, "sec: %s installed lifetime=%us",
              tr_gtkname(key_index - 1), lifetime_kde);
    } else {
        WARN("sec: ignore reinstallation of %s", tr_gtkname(key_index - 1));
    }

    return 0;
}

static void supp_key_update_gtkl(struct supp_ctx *supp, uint8_t gtkl_kde, bool is_lgtk)
{
    const uint8_t count = is_lgtk ? WS_LGTK_COUNT : WS_GTK_COUNT;
    const uint8_t offset = is_lgtk ? WS_GTK_COUNT : 0;
    struct ws_gtk *gtk;

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.5 FFN Join State 5: Operational
     * A previously installed GTK[X] is removed from the Border Router prior to
     * its expiration time. The Border Router disseminated a new PC Frame, with
     * GTK[X] hash set to 0, into the PAN. Receiving FFNs, still with local
     * GTK[X] hash value nonzero, detect the hash mismatch and attempt to
     * acquire the new GTK[X]. The acquisition attempt will reveal that GTK[X]
     * is no longer valid (via the GTKL KDEs returned by the authenticator) and
     * the FFN will remove it locally (setting its GTK[X] hash to 0).
     */
    for (int i = 0; i < count; i++) {
        gtk = &supp->gtks[i + offset];
        if ((gtkl_kde & BIT(i)) || timer_stopped(&gtk->expiration_timer))
            continue;
        TRACE(TR_SECURITY, "sec: %s revoked", tr_gtkname(i + offset));
        timer_stop(&supp->timer_group, &gtk->expiration_timer);
        if (gtk->expiration_timer.callback)
            gtk->expiration_timer.callback(&supp->timer_group, &gtk->expiration_timer);
    }
}

static int supp_key_handle_key_data(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                    struct iobuf_read *iobuf)
{
    struct pktbuf buf = { };
    bool has_lgtk, has_lgtkl;
    struct kde_gtk gtk_kde;
    bool has_gtk, has_gtkl;
    uint32_t lifetime_kde;
    const uint8_t *ptk;
    uint8_t gtkl_kde;
    int ret;

    pktbuf_init(&buf, NULL, be16toh(frame->data_length));

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tls_client.ptk.tkey;
    else
        ptk = supp->tls_client.ptk.key;

    /*
     *   IEEE 802.11-2020, 4.10.4.2 Key usage
     * In an IBSS group addressed Data frames are protected by a key, e.g.,
     * named B1, [...] B1 is sent in an EAPOL-Key frame, encrypted under the
     * EAPOL-Key encryption key (KEK) portion of the PTK [...]
     */
    ret = nist_kw_unwrap(ieee80211_kek(ptk), IEEE80211_AKM_1_KEK_LEN_BYTES * 8,
                         iobuf_ptr(iobuf), iobuf_remaining_size(iobuf), pktbuf_head(&buf), pktbuf_len(&buf));
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: nist_kw_unwrap: %s", "eapol-key", strerror(-ret));
        goto error;
    }

    has_gtk = kde_read_gtk(pktbuf_head(&buf), pktbuf_len(&buf), &gtk_kde);
    has_lgtk = kde_read_lgtk(pktbuf_head(&buf), pktbuf_len(&buf), &gtk_kde);
    if (has_gtk && has_lgtk) {
        TRACE(TR_DROP, "drop %-9s: both GTK and LGTK KDE found", "eapol-key");
        goto error;
    }
    if ((has_gtk || has_lgtk) &&
        !kde_read_lifetime(pktbuf_head(&buf), pktbuf_len(&buf), &lifetime_kde)) {
        TRACE(TR_DROP, "drop %-9s: missing Lifetime KDE", "eapol-key");
        goto error;
    }
    has_gtkl = kde_read_gtkl(pktbuf_head(&buf), pktbuf_len(&buf), &gtkl_kde);
    has_lgtkl = kde_read_lgtkl(pktbuf_head(&buf), pktbuf_len(&buf), &gtkl_kde);
    if (has_gtkl && has_lgtkl) {
        TRACE(TR_DROP, "drop %-9s: both GTKL and LGTKL KDE found", "eapol-key");
        goto error;
    }
    if ((!has_gtkl && !has_lgtkl) || (has_gtk && !has_gtkl) || (has_lgtk && !has_lgtkl)) {
        TRACE(TR_DROP, "drop %-9s: missing (L)GTKL KDE", "eapol-key");
        goto error;
    }

    if (has_gtk || has_lgtk) {
        ret = supp_key_install_gtk(supp, &gtk_kde, lifetime_kde, has_lgtk);
        if (ret < 0)
            goto error;
    }

    supp_key_update_gtkl(supp, gtkl_kde, has_lgtkl);

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE) {
        // Prevent Key Reinstallation Attacks (https://www.krackattacks.com)
        if (memcmp(supp->tls_client.ptk.key, supp->tls_client.ptk.tkey, sizeof(supp->tls_client.ptk.tkey))) {
            memcpy(supp->tls_client.ptk.key, supp->tls_client.ptk.tkey, sizeof(supp->tls_client.ptk.key));
            // TODO: callback to install TK
            TRACE(TR_SECURITY, "sec: PTK installed");
        } else {
            WARN("sec: ignore reinstallation of ptk");
        }
    }

    pktbuf_free(&buf);
    return 0;

error:
    pktbuf_free(&buf);
    return -EINVAL;
}

static void supp_key_group_message_1_recv(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                          struct iobuf_read *iobuf)
{
    TRACE(TR_SECURITY, "sec: %-8s msg=1", "rx-gkh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_ACK, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"ack\" bit not set when it should be", "eapol-key");
        return;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"mic\" bit not set when it should be", "eapol-key");
        return;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_SECURE, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"secure\" bit not set when it should be", "eapol-key");
        return;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_ENCRYPTED_DATA, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"encrypted-data\" bit not set when it should be", "eapol-key");
        return;
    }
    if (!supp_key_is_mic_valid(supp, frame, iobuf)) {
        TRACE(TR_DROP, "drop %-9s: invalid MIC", "eapol-key");
        return;
    }

    if (supp_key_handle_key_data(supp, frame, iobuf))
        return;
    supp_key_group_message_2_send(supp);
    // We may have started the key request txalg after a gtkhash missmatch
    rfc8415_txalg_stop(&supp->key_request_txalg);
}

static void supp_key_pairwise_message_3_recv(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                             struct iobuf_read *iobuf)
{
    TRACE(TR_SECURITY, "sec: %-8s msg=3", "rx-4wh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_INSTALL, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"install\" bit not set when it should be", "eapol-key");
        goto error;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_ACK, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"ack\" bit not set when it should be", "eapol-key");
        goto error;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"mic\" bit not set when it should be", "eapol-key");
        goto error;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_SECURE, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"secure\" bit not set when it should be", "eapol-key");
        goto error;
    }
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_ENCRYPTED_DATA, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"encrypted-data\" bit not set when it should be", "eapol-key");
        goto error;
    }

    /*
     *   IEEE 802.11-2020, 12.7.6.4 4-way handshake message 3
     * On reception of message 3, the Supplicant silently discards the message
     * [...] if the ANonce value in message 3 differs from the ANonce value in
     * message 1.
     */
    if (memcmp(supp->anonce, frame->nonce, sizeof(frame->nonce))) {
        TRACE(TR_DROP, "drop %-9s: invalid anonce", "eapol-key");
        goto error;
    }
    if (!supp_key_is_mic_valid(supp, frame, iobuf)) {
        TRACE(TR_DROP, "drop %-9s: invalid MIC", "eapol-key");
        goto error;
    }

    if (supp_key_handle_key_data(supp, frame, iobuf))
        goto error;
    supp_key_pairwise_message_4_send(supp);
    return;

error:
    timer_start_rel(NULL, &supp->failure_timer, supp->timeout_ms);
}

static void supp_key_pairwise_message_1_recv(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                             struct iobuf_read *data)
{
    uint8_t received_pmkid[16];
    uint8_t pmkid[16];

    TRACE(TR_SECURITY, "sec: %-8s msg=1", "rx-4wh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_ACK, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"ack\" bit not set when it should be", "eapol-key");
        goto exit;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.5.2.3 PTK and GTK Installation Flow
     * See Msg 1.
     */
    if (be16toh(frame->length) != 16) {
        TRACE(TR_DROP, "drop %-9s: invalid key length %d", "eapol-key", be16toh(frame->length));
        goto exit;
    }

    ieee80211_derive_pmkid(supp->tls_client.pmk.key, supp->authenticator_eui64, supp->eui64, pmkid);

    if (!kde_read_pmkid(iobuf_ptr(data), iobuf_remaining_size(data), received_pmkid)) {
        TRACE(TR_DROP, "drop %-9s: missing pmkid", "eapol-key");
        goto exit;
    }
    if (memcmp(received_pmkid, pmkid, sizeof(pmkid))) {
        TRACE(TR_DROP, "drop %-9s: unknown pmkid", "eapol-key");
        goto exit;
    }

    /*
     * Note: the Key Replay counter is not updated here.
     *
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * In other words, the Supplicant never updates the Key Replay Counter
     * field for message 1 in the 4-way handshake, as it includes no MIC.
     */

    ieee80211_generate_nonce(supp->eui64, supp->snonce);
    memcpy(supp->anonce, frame->nonce, sizeof(frame->nonce));
    ieee80211_derive_ptk384(supp->tls_client.pmk.key, supp->authenticator_eui64, supp->eui64, supp->anonce, supp->snonce, supp->tls_client.ptk.tkey);
    supp_key_pairwise_message_2_send(supp, frame);
    // We may have started the key request txalg after a gtkhash missmatch
    rfc8415_txalg_stop(&supp->key_request_txalg);

exit:
    timer_start_rel(NULL, &supp->failure_timer, supp->timeout_ms);
}

static void supp_key_pairwise_recv(struct supp_ctx *supp, const struct eapol_key_frame *frame,
                                   struct iobuf_read *iobuf)
{
    timer_stop(NULL, &supp->failure_timer);

    switch (FIELD_GET(IEEE80211_MASK_KEY_INFO_INSTALL, be16toh(frame->information)))
    {
    case 0:
        supp_key_pairwise_message_1_recv(supp, frame, iobuf);
        break;
    case 1:
        supp_key_pairwise_message_3_recv(supp, frame, iobuf);
        break;
    default:
        break;
    }
}

void supp_key_recv(struct supp_ctx *supp, struct iobuf_read *iobuf)
{
    const struct eapol_key_frame *frame;

    frame = iobuf_pop_data_ptr(iobuf, sizeof(*frame));
    if (!frame) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol-key frame", "eapol-key");
        return;
    }

    if (frame->descriptor_type != EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE) {
        TRACE(TR_DROP, "drop %-9s: invalid key descriptor type", "eapol-key");
        return;
    }
    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_VERSION, be16toh(frame->information)) != IEEE80211_KEY_INFO_VERSION) {
        TRACE(TR_DROP, "drop %-9s: invalid key descriptor version", "eapol-key");
        return;
    }

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * The Supplicant should also use the key replay counter and ignore
     * EAPOL-Key frames with a Key Replay Counter field value smaller than or
     * equal to any received in a valid message.
     *
     * Note: we always accept frames if our current replay counter is 0.
     * The replay counter is set to 0 after the PMK is established.
     * The replay counter is updated only when a frame with a valid MIC is
     * received.
     *
     * Therefore, we will always accept replayed 4WH msg 1 after the PMK is
     * established.
     */
    if (supp->tls_client.pmk.replay_counter && be64toh(frame->replay_counter) <= supp->tls_client.pmk.replay_counter) {
        TRACE(TR_DROP, "drop %-9s: invalid replay counter %"PRIu64, "eapol-key", be64toh(frame->replay_counter));
        return;
    }

    switch (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)))
    {
    case IEEE80211_KEY_TYPE_GROUP:
        supp_key_group_message_1_recv(supp, frame, iobuf);
        break;
    case IEEE80211_KEY_TYPE_PAIRWISE:
        supp_key_pairwise_recv(supp, frame, iobuf);
        break;
    default:
        break;
    }
}
