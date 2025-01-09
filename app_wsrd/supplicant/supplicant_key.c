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

static void supp_key_message_send(struct supplicant_ctx *supp, struct eapol_key_frame *response, uint8_t kmp_id)
{
    struct pktbuf buf = { };
    const uint8_t *ptk;
    int ret;

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * [...] the EAPOL Key MIC is a MIC of the EAPOL-Key frames, from and
     * including the EAPOL protocol version field to and including the Key Data
     * field, calculated with the Key MIC field set to 0.
     */
    pktbuf_push_tail(&buf, response, sizeof(*response));
    eapol_write_hdr_head(&buf, EAPOL_PACKET_TYPE_KEY);

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(response->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tptk;
    else
        ptk = supp->ptk;

    /*
     *   IEEE 802.11-2020, 12.7.6 4-way handshake
     * MIC(KCK, EAPOL)
     */
    ret = hmac_md_sha1(ptk, IEEE80211_AKM_1_KCK_LEN_BYTES, pktbuf_head(&buf), pktbuf_len(&buf),
                       response->mic, sizeof(response->mic));
    FATAL_ON(ret, 2, "%s: hmac_md_sha1: %s", __func__, strerror(-ret));

    // Update MIC
    pktbuf_pop_tail(&buf, NULL, sizeof(*response));
    pktbuf_push_tail(&buf, response, sizeof(*response));
    supp_send_eapol(supp, kmp_id, &buf);
    pktbuf_free(&buf);
}

static void supp_key_group_message_2_send(struct supplicant_ctx *supp)
{
    struct eapol_key_frame message = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1)),
        .replay_counter = htobe64(supp->replay_counter),
    };

    TRACE(TR_SECURITY, "sec: %-8s msg=2", "tx-gkh");
    supp_key_message_send(supp, &message, IEEE802159_KMP_ID_80211_GKH);
}

static void supp_key_pairwise_message_4_send(struct supplicant_ctx *supp)
{
    struct eapol_key_frame response = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_PAIRWISE) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1)),
        .replay_counter = htobe64(supp->replay_counter),
    };

    TRACE(TR_SECURITY, "sec: %-8s msg=4", "tx-4wh");
    supp_key_message_send(supp, &response, IEEE802159_KMP_ID_80211_4WH);
}

static void supp_key_pairwise_message_2_send(struct supplicant_ctx *supp, const struct eapol_key_frame *request)
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
    supp_key_message_send(supp, &response, IEEE802159_KMP_ID_80211_4WH);
}

static bool supp_key_is_mic_valid(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
                                  struct iobuf_read *iobuf)
{
    const uint8_t *ptk;

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tptk;
    else
        ptk = supp->ptk;

    if (!ieee80211_is_mic_valid(ptk, frame, iobuf_ptr(iobuf), iobuf_remaining_size(iobuf)))
        return false;

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * The local Key Replay Counter field should not be updated until after the
     * EAPOL-Key MIC is checked and is found to be valid.
     */
    supp->replay_counter = be64toh(frame->replay_counter);
    return true;
}

static int supp_key_handle_key_data(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
                                    struct iobuf_read *iobuf)
{
    uint8_t gtks_slot_min = 0;
    struct pktbuf buf = { };
    struct kde_gtk gtk_kde;
    uint32_t lifetime_kde;
    uint8_t gtks_size = 4;
    bool is_lgtk = false;
    const uint8_t *ptk;
    uint8_t key_index;
    uint8_t gtkl_kde;
    int ret;

    pktbuf_init(&buf, NULL, be16toh(frame->data_length));

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tptk;
    else
        ptk = supp->ptk;

    /*
     *   IEEE 802.11-2020, 4.10.4.2 Key usage
     * In an IBSS group addressed Data frames are protected by a key, e.g.,
     * named B1, [...] B1 is sent in an EAPOL-Key frame, encrypted under the
     * EAPOL-Key encryption key (KEK) portion of the PTK [...]
     */
    ret = nist_kw_unwrap(ptk + IEEE80211_AKM_1_KCK_LEN_BYTES, IEEE80211_AKM_1_KEK_LEN_BYTES * 8,
                         iobuf_ptr(iobuf), iobuf_remaining_size(iobuf), pktbuf_head(&buf), pktbuf_len(&buf));
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: nist_kw_unwrap: %s", "eapol-key", strerror(-ret));
        goto error;
    }

    if (!kde_read_gtk(pktbuf_head(&buf), pktbuf_len(&buf), &gtk_kde)) {
        if (!kde_read_lgtk(pktbuf_head(&buf), pktbuf_len(&buf), &gtk_kde)) {
            TRACE(TR_DROP, "drop %-9s: GTK and LGTK KDE not found", "eapol-key");
            goto error;
        }
        is_lgtk = true;
        gtks_size = ARRAY_SIZE(supp->gtks);
        gtks_slot_min = 4;
    }
    if (!kde_read_lifetime(pktbuf_head(&buf), pktbuf_len(&buf), &lifetime_kde)) {
        TRACE(TR_DROP, "drop %-9s: lifetime KDE not found", "eapol-key");
        goto error;
    }
    if (is_lgtk && !kde_read_lgtkl(pktbuf_head(&buf), pktbuf_len(&buf), &gtkl_kde)) {
        TRACE(TR_DROP, "drop %-9s: LGTKL KDE not found", "eapol-key");
        goto error;
    }
    if (!is_lgtk && !kde_read_gtkl(pktbuf_head(&buf), pktbuf_len(&buf), &gtkl_kde)) {
        TRACE(TR_DROP, "drop %-9s: GTKL KDE not found", "eapol-key");
        goto error;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.2.4 Group Transient Key KDE (GTK)
     * The TX field MUST be set to 0 and ignored upon reception.
     */
    if (FIELD_GET(KDE_GTK_MASK_TX, gtk_kde.flags))
        TRACE(TR_IGNORE, "ignore: unsupported GTK KDE tx bit");

    // the key ID field starts at 0
    key_index = FIELD_GET(KDE_GTK_MASK_KEY_ID, gtk_kde.flags) + 1 + gtks_slot_min;
    if (key_index > gtks_size) {
        TRACE(TR_DROP, "drop %-9s: invalid key id %u", "eapol-key", key_index - 1 - gtks_slot_min);
        goto error;
    }

    /*
     *   IEEE 802.11-2020, 12.7.7.4 Group key handshake implementation considerations
     * To prevent key reinstallation attacks, the Supplicant shall maintain a
     * copy of the most recent GTK [...] The Supplicant shall not install a GTK
     * [...] when the key to be set matches either of these two keys (see 6.3.19).
     */
    for (int i = gtks_slot_min; i < gtks_size; i++)
        if (!memcmp(supp->gtks[i].gtk, gtk_kde.gtk, sizeof(gtk_kde.gtk)) && i != key_index - 1) {
            TRACE(TR_DROP, "drop %-9s: key reinstallation detected at index %d", "eapol-key", i);
            goto error;
        }

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.5 FFN Join State 5: Operational
     * iii. A previously installed GTK[X] is removed from the Border Router prior to its expiration
     * time. The Border Router disseminated a new PC Frame, with GTK[X] hash set to 0, into the
     * PAN. Receiving FFNs, still with local GTK[X] hash value nonzero, detect the hash
     * mismatch and attempt to acquire the new GTK[X]. The acquisition attempt will reveal that
     * GTK[X] is no longer valid (via the GTKL KDEs returned by the authenticator) and the FFN
     * will remove it locally (setting its GTK[X] hash to 0).
     */
    for (int i = gtks_slot_min; i < gtks_size; i++)
        if (!(gtkl_kde & BIT(i - gtks_slot_min)) && !timer_stopped(&supp->gtks[i].expiration_timer)) {
            TRACE(TR_SECURITY, "sec: %s[%u] no longer valid", is_lgtk ? "lgtk" : "gtk", i + 1 - gtks_slot_min);
            timer_stop(NULL, &supp->gtks[i].expiration_timer);
            if (supp->gtks[i].expiration_timer.callback)
                supp->gtks[i].expiration_timer.callback(NULL, &supp->gtks[i].expiration_timer);
        }

    /*
     * Do not reinstall the key if it was already installed before to prevent Key
     * Reinstallation Attacks (KRACK)[1].
     *
     * [1]: https://www.krackattacks.com
     */
    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE) {
        if (memcmp(supp->ptk, supp->tptk, sizeof(supp->tptk))) {
            memcpy(supp->ptk, supp->tptk, sizeof(supp->ptk));
            // TODO: callback to install TK
            TRACE(TR_SECURITY, "sec: PTK installed");
        } else {
            WARN("sec: ignore reinstallation of ptk");
        }
    }
    if (memcmp(supp->gtks[key_index - 1].gtk, gtk_kde.gtk, sizeof(gtk_kde.gtk))) {
        memcpy(supp->gtks[key_index - 1].gtk, gtk_kde.gtk, sizeof(gtk_kde.gtk));
        timer_start_rel(NULL, &supp->gtks[key_index - 1].expiration_timer, lifetime_kde * 1000);
        supp->on_gtk_change(supp, gtk_kde.gtk, key_index);
        TRACE(TR_SECURITY, "sec: %s[%u] installed lifetime:%us expiration:%"PRIu64, is_lgtk ? "lgtk" : "gtk",
                key_index - gtks_slot_min, lifetime_kde, supp->gtks[key_index - 1].expiration_timer.expire_ms);
    } else {
        TRACE(TR_SECURITY, "sec: ignore reinstallation of %s[%u] ", is_lgtk ? "lgtk" : "gtk",
              key_index - gtks_slot_min);
    }

    pktbuf_free(&buf);
    return 0;

error:
    pktbuf_free(&buf);
    return -EINVAL;
}

static void supp_key_group_message_1_recv(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
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

static void supp_key_pairwise_message_3_recv(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
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

    /*
     * Wi-SUN does not specify any timeout when msg 3 is not well formatted.
     * 60 seconds is an arbitrary value.
     */
error:
    timer_start_rel(NULL, &supp->failure_timer, 60 * 1000);
}

static void supp_key_pairwise_message_1_recv(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
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

    ieee80211_derive_pmkid(supp->pmk, supp->authenticator_eui64, supp->eui64, pmkid);

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
    ieee80211_derive_ptk384(supp->pmk, supp->authenticator_eui64, supp->eui64, supp->anonce, supp->snonce, supp->tptk);
    supp_key_pairwise_message_2_send(supp, frame);
    // We may have started the key request txalg after a gtkhash missmatch
    rfc8415_txalg_stop(&supp->key_request_txalg);

exit:
    /*
     * Wi-SUN does not specify any timeout between 4wh msg 2 and 3.
     * It does not specify anything when msg 1 is not well formatted either.
     * 60 seconds is an arbitrary value.
     */
    timer_start_rel(NULL, &supp->failure_timer, 60 * 1000);
}

static void supp_key_pairwise_recv(struct supplicant_ctx *supp, const struct eapol_key_frame *frame,
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

void supp_key_recv(struct supplicant_ctx *supp, struct iobuf_read *iobuf)
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
     */
    if (supp->replay_counter != -1 && be64toh(frame->replay_counter) <= supp->replay_counter) {
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
