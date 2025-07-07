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
#include <netinet/in.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

#include "common/specs/ieee802159.h"
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/specs/ws.h"
#include "common/crypto/ieee80211.h"
#include "common/ws/eapol_relay.h"
#include "common/sys_queue_extra.h"
#include "common/named_values.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/log.h"

#include "authenticator_eap.h"
#include "authenticator_key.h"
#include "authenticator_radius.h"
#include "authenticator_storage.h"

#include "authenticator.h"

void auth_update_frame_counter(struct auth_ctx *auth, int key_index, uint32_t frame_counter)
{
    if (!ws_gtk_installed(&auth->gtks[key_index - 1]))
        return;
    auth->gtks[key_index - 1].frame_counter = frame_counter;
    auth_storage_store_keys(auth, false);
}

int auth_gtk_slot_next(int slot)
{
    if (slot < WS_GTK_COUNT)
        return slot + 1 < WS_GTK_COUNT ? slot + 1 : 0;
    else
        return slot + 1 < WS_GTK_COUNT + WS_LGTK_COUNT ? slot + 1 : WS_GTK_COUNT;
}

static void auth_gtk_expiration_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);
    struct ws_gtk *gtk = container_of(timer, struct ws_gtk, expiration_timer);
    const int slot = (int)(gtk - auth->gtks);

    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, NULL, 0, slot + 1, false);
    TRACE(TR_SECURITY, "sec: expired %s", tr_gtkname(slot));
    ws_gtk_clear(group, gtk);
    auth_storage_store_keys(auth, true);
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_NEW_ACTIVATION_TIME: The time at which the Border Router activates the
 * next GTK prior to expiration of the currently activated GTK. Expressed as a
 * fraction (1/X) of GTK_EXPIRE_OFFSET.
 */
void auth_activate_next_gtk(struct auth_ctx *auth, struct auth_gtk_group *gtk_group)
{
    const struct auth_node_cfg *cfg = gtk_group == &auth->gtk_group ?
                                      &auth->cfg->ffn : &auth->cfg->lfn;
    const uint64_t expire_ms = auth->gtks[gtk_group->slot_active].expiration_timer.expire_ms;
    const uint64_t expire_offset_ms = (uint64_t)cfg->gtk_expire_offset_s * 1000;

    if (expire_offset_ms)
        timer_start_abs(&auth->timer_group, &gtk_group->activation_timer,
                        expire_ms - expire_offset_ms / cfg->gtk_new_activation_time);
    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, NULL, 0, gtk_group->slot_active + 1, true);
    auth_storage_store_keys(auth, true);
    TRACE(TR_SECURITY, "sec: activated %s=%s", tr_gtkname(gtk_group->slot_active),
          tr_key(auth->gtks[gtk_group->slot_active].key, sizeof(auth->gtks[gtk_group->slot_active].key)));
    TRACE(TR_SECURITY, "sec: next %s activation=%"PRIu64, gtk_group == &auth->gtk_group ? "gtk" : "lgtk",
          gtk_group->activation_timer.expire_ms / 1000);
}

static void auth_gtk_activation_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_gtk_group *gtk_group = container_of(timer, struct auth_gtk_group, activation_timer);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);

    gtk_group->slot_active = auth_gtk_slot_next(gtk_group->slot_active);
    auth_activate_next_gtk(auth, gtk_group);
}

static int auth_gtk_slot_latest(const struct auth_ctx *auth, const struct auth_gtk_group *gtk_group)
{
    int slot_count = (gtk_group == &auth->gtk_group) ? WS_GTK_COUNT : WS_LGTK_COUNT;
    int slot_offset = (gtk_group == &auth->gtk_group) ? 0 : WS_GTK_COUNT;
    int slot_latest = slot_offset;
    uint64_t max_expire_ms = 0;
    uint64_t expire_ms;

    for (int i = 0; i < slot_count; i++) {
        expire_ms = auth->gtks[slot_offset + i].expiration_timer.expire_ms;
        if (expire_ms >= max_expire_ms) {
            max_expire_ms = expire_ms;
            slot_latest = slot_offset + i;
        }
    }
    return slot_latest;
}

static bool auth_is_gtk_valid(const struct auth_ctx *auth,
                              const struct auth_gtk_group *gtk_group,
                              const uint8_t gtk[16])
{
    const int slot_count = gtk_group == &auth->gtk_group ? WS_GTK_COUNT : WS_LGTK_COUNT;
    const int slot_offset = gtk_group == &auth->gtk_group ? 0 : WS_GTK_COUNT;

    if (!memzcmp(gtk, 16))
        return false;
    for (int i = 0; i < slot_count; i++)
        if (!memcmp(auth->gtks[slot_offset + i].key, gtk, 16))
            return false;
    return true;
}

int auth_install_gtk(struct auth_ctx *auth, struct auth_gtk_group *gtk_group,
                     int slot_install, const uint8_t gtk[16])
{
    const struct auth_node_cfg *cfg = gtk_group == &auth->gtk_group ?
                                      &auth->cfg->ffn : &auth->cfg->lfn;
    const struct ws_gtk *latest = &auth->gtks[auth_gtk_slot_latest(auth, gtk_group)];
    const uint64_t expire_offset_ms = (uint64_t)cfg->gtk_expire_offset_s * 1000;
    struct ws_gtk *new = &auth->gtks[slot_install];
    uint8_t gtk_rand[16];
    uint64_t start_ms;

    if (gtk) {
        if (!auth_is_gtk_valid(auth, gtk_group, gtk))
            return -EINVAL;
        memcpy(new->key, gtk, 16);
    } else {
        do {
            rand_get_n_bytes_random(gtk_rand, sizeof(gtk_rand));
        } while (!auth_is_gtk_valid(auth, gtk_group, gtk_rand));
        memcpy(new->key, gtk_rand, sizeof(gtk_rand));
    }
    new->frame_counter = 0;

    /*
     *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
     * GTK_EXPIRE_OFFSET: The expiration time of a GTK is calculated as the
     * expiration time of the GTK most recently installed at the Border Router
     * plus GTK_EXPIRE_OFFSET.
     */
    start_ms = latest->expiration_timer.expire_ms ? : time_now_ms(CLOCK_MONOTONIC);
    if (expire_offset_ms)
        timer_start_abs(&auth->timer_group, &new->expiration_timer, start_ms + expire_offset_ms);
    else
        // Start a very long timer since GTK Liveness is determined by timer_stopped()
        timer_start_abs(&auth->timer_group, &new->expiration_timer, UINT64_MAX);

    /*
     *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
     * GTK_NEW_INSTALL_REQUIRED: The amount of time elapsed in the active GTK’s
     * lifetime (as a percentage of lifetime provided in Lifetime KDE) at which
     * a new GTK must be installed on the Border Router (supporting overlapping
     * lifespans).
     * NOTE: GTK_NEW_INSTALL_REQUIRED is calculated as a percentage of
     * GTK_EXPIRE_OFFSET instead of the full lifetime of the GTK to ensure
     * consistent timings throughout the BR lifetime.
     */
    if (expire_offset_ms)
        timer_start_abs(&auth->timer_group, &gtk_group->install_timer,
                        start_ms + cfg->gtk_new_install_required * expire_offset_ms / 100);

    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, new->key, new->frame_counter, slot_install + 1, false);
    auth_storage_store_keys(auth, true);
    TRACE(TR_SECURITY, "sec: installed %s=%s expiration=%"PRIu64,
          tr_gtkname(slot_install), tr_key(new->key, sizeof(new->key)), new->expiration_timer.expire_ms / 1000);
    TRACE(TR_SECURITY, "sec: next %s installation=%"PRIu64, gtk_group == &auth->gtk_group ? "gtk" : "lgtk",
          gtk_group->install_timer.expire_ms / 1000);
    return 0;
}

int auth_revoke_gtks(struct auth_ctx *auth, struct auth_gtk_group *gtk_group,
                     const uint8_t gtk[16])
{
    const struct auth_node_cfg *cfg = gtk_group == &auth->gtk_group ?
                                      &auth->cfg->ffn : &auth->cfg->lfn;
    const int slot_count = gtk_group == &auth->gtk_group ? WS_GTK_COUNT : WS_LGTK_COUNT;
    const int slot_offset = gtk_group == &auth->gtk_group ? 0 : WS_GTK_COUNT;
    uint64_t reduced_lifetime_ms;
    uint64_t active_remaining_ms;
    uint8_t slot_latest;
    uint8_t next_slot;

    if (gtk && !auth_is_gtk_valid(auth, gtk_group, gtk))
        return -EINVAL;

    reduced_lifetime_ms = (uint64_t)cfg->gtk_expire_offset_s * 1000 / cfg->revocation_lifetime_reduction;
    active_remaining_ms = timer_remaining_ms(&auth->gtks[gtk_group->slot_active].expiration_timer);

    /*
     *   Wi-SUN FAN 1.1v09 6.5.2.5	Revocation of Node Access
     * a. If the remaining lifetime of the currently active L/GTK is greater than
     * (lifetime / LIFETIME_REDUCTION), the Border Router, atomically and in
     * specific order, MUST destroy all L/GTKs except the currently active
     * L/GTK, modify the lifetime of the currently active L/GTK to be
     * (lifetime / LIFETIME_REDUCTION), and add a new L/GTK (with normal lifetime).
     *
     * b. If the remaining lifetime of the currently active L/GTK is less than or
     * equal to (lifetime / LIFETIME_REDUCTION), the Border Router, atomically
     * and in specific order, MUST destroy all L/GTKs except the currently active
     * L/GTK and the next available L/GTK, modify the lifetime of the next available
     * L/GTK to be (lifetime / LIFETIME_REDUCTION), and add a new L/GTK (with normal lifetime).
     */
    if (active_remaining_ms > reduced_lifetime_ms) {
        for (uint8_t i = 0; i < slot_count; i++) {
            if (slot_offset + i == gtk_group->slot_active ||
                timer_stopped(&auth->gtks[slot_offset + i].expiration_timer)) {
                continue;
            }
            timer_stop(&auth->timer_group, &auth->gtks[slot_offset + i].expiration_timer);
            auth_gtk_expiration_timer_timeout(&auth->timer_group, &auth->gtks[slot_offset + i].expiration_timer);
        }
        active_remaining_ms = reduced_lifetime_ms;
        slot_latest = gtk_group->slot_active;
    } else {
        next_slot = auth_gtk_slot_next(gtk_group->slot_active);
        for (uint8_t i = 0; i < slot_count; i++) {
            if (slot_offset + i == gtk_group->slot_active ||
                slot_offset + i == next_slot ||
                timer_stopped(&auth->gtks[slot_offset + i].expiration_timer)) {
                continue;
            }
            timer_stop(&auth->timer_group, &auth->gtks[slot_offset + i].expiration_timer);
            auth_gtk_expiration_timer_timeout(&auth->timer_group, &auth->gtks[slot_offset + i].expiration_timer);
        }
        slot_latest = next_slot;
    }

    timer_start_rel(&auth->timer_group, &auth->gtks[slot_latest].expiration_timer, reduced_lifetime_ms);
    TRACE(TR_SECURITY, "sec: %s reduced expiration=%"PRIu64,
          tr_gtkname(slot_latest), auth->gtks[slot_latest].expiration_timer.expire_ms / 1000);
    auth_install_gtk(auth, gtk_group, auth_gtk_slot_next(slot_latest), gtk);
    timer_start_rel(&auth->timer_group, &gtk_group->activation_timer,
                    active_remaining_ms - (uint64_t)cfg->gtk_expire_offset_s * 1000 / cfg->gtk_new_activation_time);
    TRACE(TR_SECURITY, "sec: next %s activation=%"PRIu64, gtk_group == &auth->gtk_group ? "gtk" : "lgtk",
          gtk_group->activation_timer.expire_ms / 1000);
    return 0;
}

static void auth_gtk_install_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_gtk_group *gtk_group = container_of(timer, struct auth_gtk_group, install_timer);
    uint8_t slot_install = (uint8_t)auth_gtk_slot_next(gtk_group->slot_active);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);

    auth_install_gtk(auth, gtk_group, slot_install, NULL);
}

static void auth_install_from_gtk_init(struct auth_ctx *auth, struct auth_gtk_group *gtk_group)
{
    const int slot_count = gtk_group == &auth->gtk_group ? WS_GTK_COUNT : WS_LGTK_COUNT;
    const int slot_offset = gtk_group == &auth->gtk_group ? 0 : WS_GTK_COUNT;
    bool gap = false;
    int ret;

    for (int i = 0; i < slot_count; i++) {
        if (!memzcmp(auth->cfg->gtk_init[slot_offset + i], 16)) {
            gap = true;
        } else {
            FATAL_ON(gap, 1, "%s requires %s",
                     tr_gtkname(slot_offset + i),
                     tr_gtkname(slot_offset + i - 1));
            ret = auth_install_gtk(auth, gtk_group, slot_offset + i,
                                   auth->cfg->gtk_init[slot_offset + i]);
            FATAL_ON(ret < 0, 1, "duplicate %s=%s",
                     tr_gtkname(slot_offset + i),
                     tr_key(auth->cfg->gtk_init[slot_offset + i], 16));
        }
    }
}

void auth_rt_timer_stop(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    timer_stop(&auth->timer_group, &supp->rt_timer);
    pktbuf_free(&supp->rt_buffer);
    supp->rt_kmp_id = -1;
    supp->rt_count = 0;
}

void auth_rt_timer_start(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                         uint8_t kmp_id, const void *buf, size_t buf_len)
{
    /*
     *     IEEE 802.11-2020, 12.7.6.6 4-way handshake implementation considerations
     * If the Authenticator does not receive a reply to its messages, it shall
     * attempt dot11RSNAConfigPairwiseUpdateCount transmits of the message,
     * plus a final timeout.
     *     RFC 3748 4.1. Request and Response
     * The authenticator is responsible for retransmitting Request messages. If
     * the Request message is obtained from elsewhere (such as from a backend
     * authentication server), then the authenticator will need to save a copy
     * of the Request in order to accomplish this.
     *     RFC 2865 2.4. Why UDP?
     * As noted, using UDP requires one thing which is built into TCP: with UDP
     * we must artificially manage retransmission timers to the same server,
     * although they don't require the same attention to timing provided by TCP.
     */
    auth_rt_timer_stop(auth, supp);
    pktbuf_init(&supp->rt_buffer, buf, buf_len);
    supp->rt_kmp_id = kmp_id;
    supp->rt_count  = 0;
    timer_start_rel(&auth->timer_group, &supp->rt_timer, supp->rt_timer.period_ms);
}

static void auth_remove_supp(struct auth_ctx *auth, struct auth_supp_ctx *supp)
{
    auth_rt_timer_stop(auth, supp);
    tls_free_client(&supp->eap_tls.tls);
    auth_storage_clear_supplicant(supp);
    SLIST_REMOVE(&auth->supplicants, supp, auth_supp_ctx, link);
    free(supp);
}

static void auth_rt_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_supp_ctx *supp = container_of(timer, struct auth_supp_ctx, rt_timer);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);

    BUG_ON(supp->rt_kmp_id == -1);
    supp->rt_count++;

    /*
     *     IEEE 802.11-2020 C.3 MIB detail
     * dot11RSNAConfigPairwiseUpdateCount [...] DEFVAL { 3 }
     *     RFC 3748 4.3. Retransmission Behavior
     * A maximum of 3-5 retransmissions is suggested.
     */
    if (supp->rt_count == 3) {
        TRACE(TR_SECURITY, "sec: %s max retry count exceeded eui64=%s",
              supp->rt_kmp_id ? "eapol" : "radius", tr_eui64(supp->eui64.u8));
        if (!supp->rt_kmp_id)
            supp->radius.id = -1; // Cancel transaction
        auth_rt_timer_stop(auth, supp);
        if (!auth_is_supp_pmk_valid(auth, supp))
            auth_remove_supp(auth, supp);
        return;
    }
    TRACE(TR_SECURITY, "sec: %s frame retry eui64=%s",
          supp->rt_kmp_id ? "eapol" : "radius", tr_eui64(supp->eui64.u8));

    // Update replay counter and MIC on retry
    if (supp->rt_kmp_id == IEEE802159_KMP_ID_80211_4WH || supp->rt_kmp_id == IEEE802159_KMP_ID_80211_GKH)
        auth_key_refresh_rt_buffer(supp);

    if (supp->rt_kmp_id)
        auth_send_eapol(auth, supp, supp->rt_kmp_id,
                        pktbuf_head(&supp->rt_buffer),
                        pktbuf_len(&supp->rt_buffer));
    else
        radius_send(auth, supp,
                    pktbuf_head(&supp->rt_buffer),
                    pktbuf_len(&supp->rt_buffer));
}

struct auth_supp_ctx *auth_get_supp(struct auth_ctx *auth, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp;

    SLIST_FIND(supp, &auth->supplicants, link, eui64_eq(&supp->eui64, eui64));
    return supp;
}

struct auth_supp_ctx *auth_fetch_supp(struct auth_ctx *auth, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp = auth_get_supp(auth, eui64);

    if (supp)
        return supp;

    supp = zalloc(sizeof(struct auth_supp_ctx));
    supp->eui64 = *eui64;
    supp->radius.id = -1;
    supp->last_installed_key_slot = -1;
    supp->rt_kmp_id = -1;
    supp->rt_timer.period_ms = auth->timeout_ms;
    supp->rt_timer.callback = auth_rt_timer_timeout;
    if (auth->radius_fd < 0)
        tls_init_client(&auth->tls, &supp->eap_tls.tls);
    rand_get_n_bytes_random(supp->anonce, sizeof(supp->anonce));
    SLIST_INSERT_HEAD(&auth->supplicants, supp, link);
    TRACE(TR_SECURITY, "sec: %-8s eui64=%s", "supp add", tr_eui64(supp->eui64.u8));
    return supp;
}

int auth_revoke_pmk(struct auth_ctx *auth, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp;

    supp = auth_get_supp(auth, eui64);
    if (!supp)
        return -ENODEV;
    auth_remove_supp(auth, supp);
    return 0;
}

bool auth_get_supp_tk(struct auth_ctx *auth, const struct eui64 *eui64, uint8_t tk[16])
{
    struct auth_supp_ctx *supp = auth_get_supp(auth, eui64);

    if (!supp)
        return false;
    if (!memzcmp(supp->eap_tls.tls.ptk.key, sizeof(supp->eap_tls.tls.ptk.key)))
        return false;
    memcpy(tk, ieee80211_tk(supp->eap_tls.tls.ptk.key), IEEE80211_AKM_1_TK_LEN_BYTES);
    return true;
}

void auth_send_eapol(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                     uint8_t kmp_id, const void *buf, size_t buf_len)
{
    const struct eapol_hdr *hdr;

    if (IN6_IS_ADDR_UNSPECIFIED(&supp->eapol_target)) {
        BUG_ON(buf_len < sizeof(*hdr));
        hdr = buf;
        TRACE(TR_SECURITY, "sec: %-8s type=%s length=%u", "tx-eapol",
              val_to_str(hdr->packet_type, eapol_frames, "[UNK]"), be16toh(hdr->packet_body_length));
        auth->sendto_mac(auth, kmp_id, buf, buf_len, &supp->eui64);
    } else {
        eapol_relay_send(auth->eapol_relay_fd, buf, buf_len,
                         &supp->eapol_target, &supp->eui64, kmp_id);
    }
}

void auth_recv_eapol(struct auth_ctx *auth, uint8_t kmp_id, const struct eui64 *eui64,
                     const uint8_t *buf, size_t buf_len)
{
    struct auth_supp_ctx *supp;
    const struct eapol_hdr *eapol_hdr;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    eapol_hdr = (const struct eapol_hdr *)iobuf_pop_data_ptr(&iobuf, sizeof(struct eapol_hdr));
    if (!eapol_hdr) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol header", "eapol");
        return;
    }
    if (eapol_hdr->protocol_version != EAPOL_PROTOCOL_VERSION) {
        TRACE(TR_DROP, "drop %-9s: unsupported eapol protocol version %d", "eapol", eapol_hdr->protocol_version);
        return;
    }

    if ((kmp_id == IEEE802159_KMP_ID_80211_4WH && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_KEY) ||
        (kmp_id == IEEE802159_KMP_ID_80211_GKH && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_KEY) ||
        (kmp_id != IEEE802159_KMP_ID_8021X     && eapol_hdr->packet_type == EAPOL_PACKET_TYPE_EAP)) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet type %s for KMP ID %d", "eapol",
              val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), kmp_id);
        return;
    }

    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%d", "rx-eapol",
          val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), ntohs(eapol_hdr->packet_body_length));

    supp = auth_fetch_supp(auth, eui64);

    /*
     * Since we are the initiator of all messages following a Key-Request, we
     * can easily determine the expected KMP ID. Note a Key-Request will always
     * be accepted.
     */
    if (supp->rt_kmp_id == kmp_id ||
        (kmp_id == IEEE802159_KMP_ID_8021X && eapol_hdr->packet_type == EAPOL_PACKET_TYPE_KEY)) {
        switch (eapol_hdr->packet_type) {
        case EAPOL_PACKET_TYPE_EAP:
            auth_eap_recv(auth, supp, iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf));
            break;
        case EAPOL_PACKET_TYPE_KEY:
            auth_key_recv(auth, supp, iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf));
            break;
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported eapol packet type %d", "eapol", eapol_hdr->packet_type);
            break;
        }
    } else {
        TRACE(TR_DROP, "drop %-9s: invalid KMP ID expected=%d actual=%d", "eapol", supp->rt_kmp_id, kmp_id);
    }

    /*
     * If the supplicant's retry timer is not running and has no PMK installed,
     * it means the supplicant either sent us a garbage packet, or has failed
     * the EAP-TLS handshake. In this case, we remove the supplicant from the
     * list of supplicants. This prevents an attacker from allocating a heinous
     * amount of supplicants to exhaust the authenticator's memory.
     */
    if (timer_stopped(&supp->rt_timer) && !auth_is_supp_pmk_valid(auth, supp))
        auth_remove_supp(auth, supp);
}

void auth_start(struct auth_ctx *auth, const struct eui64 *eui64, bool enable_lfn)
{
    BUG_ON(auth->radius_fd >= 0);
    BUG_ON(!auth->sendto_mac);
    BUG_ON(!auth->cfg);

    if (auth->cfg->radius_addr.ss_family != AF_UNSPEC)
        radius_init(auth, (const struct sockaddr *)&auth->cfg->radius_addr);
    else
        tls_init(&auth->tls, MBEDTLS_SSL_IS_SERVER, &auth->cfg->tls);

    SLIST_INIT(&auth->supplicants);
    timer_group_init(&auth->timer_group);
    auth->eui64 = *eui64;
    auth->gtk_group.activation_timer.callback = auth_gtk_activation_timer_timeout;
    auth->gtk_group.install_timer.callback    = auth_gtk_install_timer_timeout;
    auth->gtk_group.slot_active = 0;
    auth->lgtk_group.activation_timer.callback = auth_gtk_activation_timer_timeout;
    auth->lgtk_group.install_timer.callback    = auth_gtk_install_timer_timeout;
    auth->lgtk_group.slot_active = 4;
    for (int i = 0; i < ARRAY_SIZE(auth->gtks); i++)
        auth->gtks[i].expiration_timer.callback = auth_gtk_expiration_timer_timeout;

    if (auth_storage_load(auth)) {
        if (memzcmp(auth->cfg->gtk_init, sizeof(auth->cfg->gtk_init)))
            FATAL(1, "cannot hardcode (l)gtk value while loading previous authenticator context from storage");
        auth_storage_store_keys(auth, true);
        return;
    }

    if (memzcmp(auth->cfg->gtk_init, sizeof(*auth->cfg->gtk_init) * WS_GTK_COUNT))
        auth_install_from_gtk_init(auth, &auth->gtk_group);
    else
        auth_install_gtk(auth, &auth->gtk_group, auth->gtk_group.slot_active, NULL);
    auth_activate_next_gtk(auth, &auth->gtk_group);

    if (enable_lfn) {
        if (memzcmp(&auth->cfg->gtk_init[WS_GTK_COUNT], sizeof(*auth->cfg->gtk_init) * WS_LGTK_COUNT))
            auth_install_from_gtk_init(auth, &auth->lgtk_group);
        else
            auth_install_gtk(auth, &auth->lgtk_group, auth->lgtk_group.slot_active, NULL);
        auth_activate_next_gtk(auth, &auth->lgtk_group);
    }
    auth_storage_store_keys(auth, true);
}
