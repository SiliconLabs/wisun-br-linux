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
#include <inttypes.h>
#include <endian.h>
#include <errno.h>

#include "common/specs/ieee802159.h"
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/specs/ws.h"
#include "common/crypto/ieee80211.h"
#include "common/crypto/hmac_md.h"
#include "common/crypto/nist_kw.h"
#include "common/crypto/ws_keys.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/kde.h"
#include "common/log.h"

#include "authenticator.h"
#include "authenticator_eap.h"

#include "authenticator_key.h"

static int auth_key_get_key_slot_missmatch(struct ws_gtk *gtks, int gtks_size, uint8_t gtkl)
{
    for (int i = 0; i < gtks_size; i++)
        if (!timer_stopped(&gtks[i].expiration_timer) && !(gtkl & BIT(i)))
            return i;
    return -1;
}

static uint8_t auth_key_get_gtkl(struct ws_gtk *gtks, int gtks_size)
{
    uint8_t gtkl = 0;

    for (int i = 0; i < gtks_size; i++)
        if (!timer_stopped(&gtks[i].expiration_timer))
            gtkl |= BIT(i);
    return gtkl;
}

/*
 *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
 * If the Key Data field uses the NIST AES key wrap, then the Key Data field shall
 * be padded before encrypting if the key data length is less than 16 octets or if
 * it is not a multiple of 8. The padding consists of appending a single octet 0xdd
 * followed by zero or more 0x00 octets.
 */
static void auth_key_add_kde_padding(struct pktbuf *buf)
{
    int padding_size = 8 - pktbuf_len(buf) % 8;

    if (!padding_size && pktbuf_len(buf) > 16)
        return;
    if (pktbuf_len(buf) < 16)
        padding_size = 16 - pktbuf_len(buf);
    pktbuf_push_tail_u8(buf, 0xdd);
    padding_size--;
    pktbuf_push_tail(buf, NULL, padding_size);
}

static void auth_key_message_set_mic(const uint8_t ptk[48], struct pktbuf *message)
{
    struct eapol_key_frame *frame = (struct eapol_key_frame *)(pktbuf_head(message) + sizeof(struct eapol_hdr));
    uint8_t mic[16];

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * [...] the EAPOL Key MIC is a MIC of the EAPOL-Key frames, from and
     * including the EAPOL protocol version field to and including the Key Data
     * field, calculated with the Key MIC field set to 0.
     *
     *   IEEE 802.11-2020, 12.7.6 4-way handshake
     * MIC(KCK, EAPOL)
     */
    memset(frame->mic, 0, sizeof(frame->mic));
    hmac_md_sha1(ieee80211_kck(ptk), IEEE80211_AKM_1_KCK_LEN_BYTES, pktbuf_head(message), pktbuf_len(message),
                 mic, sizeof(mic));

    // Update MIC
    memcpy(frame->mic, mic, sizeof(mic));
}

static bool auth_key_accept_frame(struct auth_supp_ctx *supp, const struct eapol_key_frame *frame,
                                  const void *data, size_t data_len)
{
    const uint8_t *ptk;

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tptk;
    else
        ptk = supp->ptk;

    if (!ieee80211_is_mic_valid(ptk, frame, data, data_len))
        return false;

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * The local Key Replay Counter field should not be updated until after the
     * EAPOL-Key MIC is checked and is found to be valid.
     */
    supp->eap_tls.tls.pmk.replay_counter++;
    return true;
}

void auth_key_refresh_rt_buffer(struct auth_supp_ctx *supp)
{
    struct eapol_key_frame *frame = (struct eapol_key_frame *)(pktbuf_head(&supp->rt_buffer) + sizeof(struct eapol_hdr));

    supp->eap_tls.tls.pmk.replay_counter++;
    frame->replay_counter = htobe64(supp->eap_tls.tls.pmk.replay_counter);
    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information)))
        return;
    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        auth_key_message_set_mic(supp->tptk, &supp->rt_buffer);
    else
        auth_key_message_set_mic(supp->ptk, &supp->rt_buffer);
}

static void auth_key_message_send(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                  struct eapol_key_frame *frame, const uint8_t *key_data, size_t key_data_len)
{
    struct pktbuf message = { };
    const uint8_t *ptk;
    uint8_t kmp_id;

    frame->replay_counter = htobe64(supp->eap_tls.tls.pmk.replay_counter);
    frame->data_length = htobe16(key_data_len);

    pktbuf_push_tail(&message, frame, sizeof(*frame));
    pktbuf_push_tail(&message, key_data, key_data_len);
    eapol_write_hdr_head(&message, EAPOL_PACKET_TYPE_KEY);

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE) {
        ptk = supp->tptk;
        kmp_id = IEEE802159_KMP_ID_80211_4WH;
    } else {
        ptk = supp->ptk;
        kmp_id = IEEE802159_KMP_ID_80211_GKH;
    }

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information)))
        auth_key_message_set_mic(ptk, &message);

    auth_send_eapol(auth, supp, kmp_id, pktbuf_head(&message), pktbuf_len(&message));
    auth_rt_timer_start(auth, supp, kmp_id, pktbuf_head(&message), pktbuf_len(&message));
}

static void auth_key_write_key_data(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                    const struct eapol_key_frame *frame, int key_slot, struct pktbuf *enc_key_data)
{
    struct pktbuf key_data = { };
    const uint8_t *ptk;
    int ret;

    /*
     * Wi-SUN requires a handshake to update the GTKL and remove a key when it
     * is revoked earlier than expected from the Lifetime KDE. This handshake
     * is ambiguous because the supplicant may already have all the other GTKs,
     * in which case the authenticator does not know which key to install. No
     * GTK KDE is provided to prevent any potential Key Reinstallation Attack
     * (KRACK).
     */
    if (key_slot >= 0) {
        kde_write_gtk(&key_data, key_slot, auth->gtks[key_slot].key);
        kde_write_lifetime(&key_data, timer_remaining_ms(&auth->gtks[key_slot].expiration_timer) / 1000);
    }
    kde_write_gtkl(&key_data, auth_key_get_gtkl(auth->gtks, ARRAY_SIZE(auth->gtks)));

    auth_key_add_kde_padding(&key_data);

    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information)) == IEEE80211_KEY_TYPE_PAIRWISE)
        ptk = supp->tptk;
    else
        ptk = supp->ptk;

    /*
     *   IEEE 802.11-2020, 4.10.4.2 Key usage
     * In an IBSS group addressed Data frames are protected by a key, e.g.,
     * named B1, [...] B1 is sent in an EAPOL-Key frame, encrypted under the
     * EAPOL-Key encryption key (KEK) portion of the PTK [...]
     *
     * Note: +8 for mbedtls_nist_kw_wrap requirements, see mbedtls/nist_kw.h
     */
    pktbuf_init(enc_key_data, NULL, pktbuf_len(&key_data) + 8);
    ret = nist_kw_wrap(ieee80211_kek(ptk), IEEE80211_AKM_1_KEK_LEN_BYTES * 8,
                       pktbuf_head(&key_data), pktbuf_len(&key_data), pktbuf_head(enc_key_data), pktbuf_len(enc_key_data));
    FATAL_ON(-ret == EINVAL, 2, "%s: nist_kw_wrap: %s", __func__, strerror(-ret));

    pktbuf_free(&key_data);
}

static void auth_key_group_message_1_send(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                          int key_slot)
{
    struct eapol_key_frame message = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_GROUP) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_ACK, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_ENCRYPTED_DATA, 1)),
        // Replay counter is taken care of in auth_key_message_send()
    };
    struct pktbuf enc_key_data = { };

    auth_key_write_key_data(auth, supp, &message, key_slot, &enc_key_data);

    TRACE(TR_SECURITY, "sec: %-8s msg=1", "tx-gkh");
    auth_key_message_send(auth, supp, &message, pktbuf_head(&enc_key_data), pktbuf_len(&enc_key_data));
    supp->last_installed_key_slot = key_slot;

    pktbuf_free(&enc_key_data);
}

static int auth_key_handshake_done(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    int next_key_slot;

    if (supp->last_installed_key_slot >= 0) {
        if (auth->on_supp_gtk_installed)
            auth->on_supp_gtk_installed(auth, &supp->eui64, supp->last_installed_key_slot + 1);
        supp->gtkl |= BIT(supp->last_installed_key_slot);
    }
    supp->last_installed_key_slot = -1;

    next_key_slot = auth_key_get_key_slot_missmatch(auth->gtks, ARRAY_SIZE(auth->gtks), supp->gtkl);
    if (next_key_slot != -1)
        auth_key_group_message_1_send(auth, supp, next_key_slot);
    // TODO: LGTK

    return 0;
}

static int auth_key_group_message_2_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                         const struct eapol_key_frame *frame,
                                         const void *data, size_t data_len)
{
    TRACE(TR_SECURITY, "sec: %-8s msg=2", "rx-gkh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"mic\" bit not set when it should be", "eapol-key");
        return -EINVAL;
    }
    if (!auth_key_accept_frame(supp, frame, data, data_len)) {
        TRACE(TR_DROP, "drop %-9s: invalid MIC", "eapol-key");
        return -EINVAL;
    }
    return auth_key_handshake_done(auth, supp);
}

static int auth_key_pairwise_message_4_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                            const struct eapol_key_frame *frame,
                                            const void *data, size_t data_len)
{
    TRACE(TR_SECURITY, "sec: %-8s msg=4", "rx-4wh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"mic\" bit not set when it should be", "eapol-key");
        return -EINVAL;
    }
    if (!auth_key_accept_frame(supp, frame, data, data_len)) {
        TRACE(TR_DROP, "drop %-9s: invalid MIC", "eapol-key");
        return -EINVAL;
    }
    memcpy(supp->ptk, supp->tptk, sizeof(supp->ptk));
    if (auth->cfg->ptk_lifetime_s)
        supp->ptk_expiration_s = time_now_s(CLOCK_MONOTONIC) + auth->cfg->ptk_lifetime_s;
    else
        supp->ptk_expiration_s = UINT64_MAX;
    return auth_key_handshake_done(auth, supp);
}

static void auth_key_pairwise_message_3_send(struct auth_ctx *auth, struct auth_supp_ctx *supp, int key_slot)
{
    struct eapol_key_frame message = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_PAIRWISE) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_INSTALL, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_ACK, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_MIC, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_SECURE, 1) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_ENCRYPTED_DATA, 1)),
        .length = htobe16(16),
        // Replay counter is taken care of in auth_key_message_send()
    };
    struct pktbuf enc_key_data = { };

    memcpy(message.nonce, supp->anonce, sizeof(message.nonce));
    auth_key_write_key_data(auth, supp, &message, key_slot, &enc_key_data);

    TRACE(TR_SECURITY, "sec: %-8s msg=3", "tx-4wh");
    auth_key_message_send(auth, supp, &message, pktbuf_head(&enc_key_data), pktbuf_len(&enc_key_data));
    supp->last_installed_key_slot = key_slot;

    pktbuf_free(&enc_key_data);
}

static int auth_key_pairwise_message_2_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                            const struct eapol_key_frame *frame,
                                            const void *data, size_t data_len)
{
    int next_key_slot;

    TRACE(TR_SECURITY, "sec: %-8s msg=2", "rx-4wh");

    if (!FIELD_GET(IEEE80211_MASK_KEY_INFO_MIC, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"mic\" bit not set when it should be", "eapol-key");
        return -EINVAL;
    }

    memcpy(supp->snonce, frame->nonce, sizeof(supp->snonce));
    ieee80211_derive_ptk384(supp->eap_tls.tls.pmk.key, auth->eui64.u8, supp->eui64.u8, supp->anonce, supp->snonce, supp->tptk);
    if (!auth_key_accept_frame(supp, frame, data, data_len)) {
        TRACE(TR_DROP, "drop %-9s: invalid MIC", "eapol-key");
        return -EINVAL;
    }
    next_key_slot = auth_key_get_key_slot_missmatch(auth->gtks, ARRAY_SIZE(auth->gtks), supp->gtkl);
    auth_key_pairwise_message_3_send(auth, supp, next_key_slot);
    return 0;
}

void auth_key_pairwise_message_1_send(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    struct eapol_key_frame message = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_TYPE, IEEE80211_KEY_TYPE_PAIRWISE) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_ACK, 1)),
        .length = htobe16(16),
        // Replay counter is taken care of in auth_key_message_send()
    };
    struct pktbuf key_data = { };
    uint8_t pmkid[16];

    ieee80211_generate_nonce(auth->eui64.u8, supp->anonce);
    memcpy(message.nonce, supp->anonce, sizeof(message.nonce));
    ieee80211_derive_pmkid(supp->eap_tls.tls.pmk.key, auth->eui64.u8, supp->eui64.u8, pmkid);
    kde_write_pmkid(&key_data, pmkid);

    TRACE(TR_SECURITY, "sec: %-8s msg=1", "tx-4wh");
    auth_key_message_send(auth, supp, &message, pktbuf_head(&key_data), pktbuf_len(&key_data));
    pktbuf_free(&key_data);
}

static int auth_key_pairwise_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                  const struct eapol_key_frame *frame,
                                  const void *data, size_t data_len)
{
    int ret = 0;

    switch (FIELD_GET(IEEE80211_MASK_KEY_INFO_SECURE, be16toh(frame->information))) {
    case 0:
        ret = auth_key_pairwise_message_2_recv(auth, supp, frame, data, data_len);
        break;
    case 1:
        ret = auth_key_pairwise_message_4_recv(auth, supp, frame, data, data_len);
        break;
    default:
        break;
    }
    return ret;
}

static bool auth_is_pmkid_valid(struct auth_ctx *auth, struct auth_supp_ctx *supp, const uint8_t pmkid_kde[16])
{
    const struct tls_pmk *pmk = &supp->eap_tls.tls.pmk;
    uint8_t pmkid[16];

    ieee80211_derive_pmkid(pmk->key, auth->eui64.u8, supp->eui64.u8, pmkid);
    if (memcmp(pmkid_kde, pmkid, 16))
        return false;
    if (!auth->cfg->pmk_lifetime_s) // Infinite lifetime
        return true;
    return time_now_s(CLOCK_MONOTONIC) < pmk->installation_s + auth->cfg->pmk_lifetime_s;
}

static bool auth_is_ptkid_valid(struct auth_ctx *auth, struct auth_supp_ctx *supp, const uint8_t ptkid_kde[16])
{
    uint8_t ptkid[16];

    ws_derive_ptkid(supp->ptk, auth->eui64.u8, supp->eui64.u8, ptkid);
    if (memcmp(ptkid_kde, ptkid, 16))
        return false;
    return time_now_s(CLOCK_MONOTONIC) < supp->ptk_expiration_s;
}

static void auth_key_request_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                  const struct eapol_key_frame *frame,
                                  const void *data, size_t data_len)
{
    uint8_t pmkid[16], ptkid[16];
    uint8_t received_node_role;
    int next_key_slot;

    TRACE(TR_SECURITY, "sec: %-8s", "rx-key-req");

    if (!kde_read_gtkl(data, data_len, &supp->gtkl))
        supp->gtkl = 0;

    /*
     *   Wi-SUN FAN 1.1v08, 6.5.2.2 Authentication and PMK Installation Flow
     * PMKID KDE MUST be present if the PMK is live. Absence of the PMKID KDE means the
     * Authenticator MUST install a new PMK and PTK on the SUP (execute EAP-TLS to
     * install a PMK and execute the 4-way the handshake to install a PTK).
     */
    if (!kde_read_pmkid(data, data_len, pmkid) || !auth_is_pmkid_valid(auth, supp, pmkid)) {
        TRACE(TR_SECURITY, "sec: pmk out-of-date starting EAP-TLS");
        auth_eap_send_request_identity(auth, supp);
        return;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.5.2.2 Authentication and PMK Installation Flow
     * The PTKID KDE MUST be present if the PTK is live. Absence of the PTKID KDE
     * means the Authenticator MUST install a new PTK on the SUP (execute the 4-way the
     * handshake to install a PTK).
     */
    if (!kde_read_ptkid(data, data_len, ptkid) || !auth_is_ptkid_valid(auth, supp, ptkid)) {
        TRACE(TR_SECURITY, "sec: ptk out-of-date starting 4wh");
        auth_key_pairwise_message_1_send(auth, supp);
        return;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.5.2.2 Authentication and PMK Installation Flow
     * The Node Role KDE MUST be present to indicate the node is operating as a FAN 1.1
     * FFN or LFN. Absence of the Node Role KDE MUST be interpreted to mean the node is
     * operating as a FAN 1.0 Router. The Node Role KDE is used to determine appropriate
     * role based lifetimes for PMKs/PTKs.
     */
    if (kde_read_nr(data, data_len, &received_node_role))
        supp->is_lfn = received_node_role == WS_NR_ROLE_LFN;

    if (supp->gtkl != auth_key_get_gtkl(auth->gtks, ARRAY_SIZE(auth->gtks))) {
        TRACE(TR_SECURITY, "sec: gtkl out-of-date starting 2wh");
        next_key_slot = auth_key_get_key_slot_missmatch(auth->gtks, ARRAY_SIZE(auth->gtks), supp->gtkl);
        auth_key_group_message_1_send(auth, supp, next_key_slot);
    }
    // TODO: check LGTKL
}

void auth_key_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                   const void *buf, size_t buf_len)
{
    const struct eapol_key_frame *frame;
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };
    const void *data;
    int ret = 0;

    frame = (const struct eapol_key_frame *)iobuf_pop_data_ptr(&iobuf, sizeof(struct eapol_key_frame));
    data = frame ? iobuf_pop_data_ptr(&iobuf, be16toh(frame->data_length)) : NULL;
    if (!data) {
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
     * 9) Request (bit 11)
     * [...]
     * The Supplicant shall not set this bit to 1 in on-going 4-way handshakes, i.e.,
     * the Key Ack bit (bit 7) shall not be set to 1 in any message in which the Request
     * bit is 1.
     *
     *   IEEE 802.11-2020, 12.7.6.6 4-way handshake implementation considerations
     * The Authenticator should ignore EAPOL-Key frames it is not expecting in reply to
     * messages it has sent or EAPOL-Key frames in which the Ack bit is 1. This stops
     * an attacker from sending the first message to the Supplicant who responds to the
     * Authenticator.
     */
    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_ACK, be16toh(frame->information))) {
        TRACE(TR_DROP, "drop %-9s: \"ack\" bit set when it should not be", "key-req");
        return;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.5.2.2 Authentication and PMK Installation Flows
     * To initiate this authentication message flow, a SUP MUST transmit an
     * EAPOL-KEY frame to its EAPOL Target node.
     *
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * 9) Request (bit 11)
     * is set to 1 by a Supplicant to request that the Authenticator initiate either a
     * 4-way handshake or group key handshake
     */
    if (FIELD_GET(IEEE80211_MASK_KEY_INFO_REQ, be16toh(frame->information)))
        return auth_key_request_recv(auth, supp, frame, data, be16toh(frame->data_length));

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter.
     * [...]
     * The Authenticator should use the key replay counter to identify invalid messages
     * to silently discard.
     */
    if (be64toh(frame->replay_counter) != supp->eap_tls.tls.pmk.replay_counter) {
        TRACE(TR_DROP, "drop %-9s: invalid replay counter %"PRIu64, "eapol-key", be64toh(frame->replay_counter));
        return;
    }

    timer_stop(&auth->timer_group, &supp->rt_timer);

    switch (FIELD_GET(IEEE80211_MASK_KEY_INFO_TYPE, be16toh(frame->information))) {
    case IEEE80211_KEY_TYPE_GROUP:
        ret = auth_key_group_message_2_recv(auth, supp, frame, data, be16toh(frame->data_length));
        break;
    case IEEE80211_KEY_TYPE_PAIRWISE:
        ret = auth_key_pairwise_recv(auth, supp, frame, data, be16toh(frame->data_length));
        break;
    }
    // If there was an error during parsing of the message, restart retry timer
    if (ret)
        timer_start_rel(&auth->timer_group, &supp->rt_timer, supp->rt_timer.period_ms);
}
