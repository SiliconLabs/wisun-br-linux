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
#include <string.h>

#include "common/specs/ieee802159.h"
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/crypto/ieee80211.h"
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

#include "authenticator.h"

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_EXPIRE_OFFSET: The expiration time of a GTK is calculated as the
 * expiration time of the GTK most recently installed at the Border Router
 * plus GTK_EXPIRE_OFFSET.
 */
static void auth_gtk_expiration_timer_start(struct auth_ctx *auth, struct ws_gtk *gtk, const struct ws_gtk *prev)
{
    const uint64_t start_ms = prev->expiration_timer.expire_ms ? : time_now_ms(CLOCK_MONOTONIC);
    const uint64_t expire_offset_ms = (uint64_t)auth->cfg->gtk_expire_offset_s * 1000;

    if (expire_offset_ms)
        timer_start_abs(&auth->timer_group, &gtk->expiration_timer, start_ms + expire_offset_ms);
    else
        // Start a very long timer since GTK Liveness is determined by timer_stopped()
        timer_start_abs(&auth->timer_group, &gtk->expiration_timer, UINT64_MAX);
}

static void auth_gtk_expiration_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);
    struct ws_gtk *gtk = container_of(timer, struct ws_gtk, expiration_timer);
    const int slot = (int)(gtk - auth->gtks);

    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, NULL, slot + 1, false);
    TRACE(TR_SECURITY, "sec: expired gtk=%s", tr_key(gtk->key, sizeof(gtk->key)));
    memset(gtk->key, 0, sizeof(gtk->key));
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_NEW_ACTIVATION_TIME: The time at which the Border Router activates the
 * next GTK prior to expiration of the currently activated GTK. Expressed as a
 * fraction (1/X) of GTK_EXPIRE_OFFSET.
 */
static void auth_gtk_activation_timer_start(struct auth_ctx *auth, struct auth_gtk_group *gtk_group)
{
    const uint64_t expire_ms = auth->gtks[gtk_group->slot_active].expiration_timer.expire_ms;
    const uint64_t expire_offset_ms = (uint64_t)auth->cfg->gtk_expire_offset_s * 1000;

    if (expire_offset_ms)
        timer_start_abs(&auth->timer_group, &gtk_group->activation_timer,
                        expire_ms - expire_offset_ms / auth->cfg->gtk_new_activation_time);
}

static void auth_gtk_activation_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_gtk_group *gtk_group = container_of(timer, struct auth_gtk_group, activation_timer);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);

    gtk_group->slot_active = (gtk_group->slot_active + 1) % WS_GTK_COUNT;
    auth_gtk_activation_timer_start(auth, gtk_group);
    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, auth->gtks[gtk_group->slot_active].key, gtk_group->slot_active + 1, true);
    TRACE(TR_SECURITY, "sec: activated gtk=%s expiration=%"PRIu64" next_install=%"PRIu64" next_activation=%"PRIu64,
          tr_key(auth->gtks[gtk_group->slot_active].key, sizeof(auth->gtks[gtk_group->slot_active].key)),
          auth->gtks[gtk_group->slot_active].expiration_timer.expire_ms / 1000,
          gtk_group->install_timer.expire_ms / 1000,
          gtk_group->activation_timer.expire_ms / 1000);
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_NEW_INSTALL_REQUIRED: The amount of time elapsed in the active GTK’s
 * lifetime (as a percentage of lifetime provided in Lifetime KDE) at which a
 * new GTK must be installed on the Border Router (supporting overlapping
 * lifespans).
 */
static void auth_gtk_install_timer_start(struct auth_ctx *auth, const struct ws_gtk *gtk)
{
    uint64_t lifetime_ms = timer_duration_ms(&gtk->expiration_timer);
    uint64_t start_ms = gtk->expiration_timer.start_ms;

    if (auth->cfg->gtk_expire_offset_s)
        timer_start_abs(&auth->timer_group, &auth->gtk_group.install_timer,
                        start_ms + lifetime_ms * auth->cfg->gtk_new_install_required / 100);
}

static void auth_gtk_install_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_gtk_group *gtk_group = container_of(timer, struct auth_gtk_group, install_timer);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);
    struct ws_gtk *cur, *new;
    int slot_install;

    cur = &auth->gtks[gtk_group->slot_active];
    if (timer_stopped(&cur->expiration_timer))
        slot_install = gtk_group->slot_active;
    else
        slot_install = (gtk_group->slot_active + 1) % WS_GTK_COUNT;
    new = &auth->gtks[slot_install];

    rand_get_n_bytes_random(new->key, sizeof(new->key));
    auth_gtk_expiration_timer_start(auth, new, cur);
    auth_gtk_install_timer_start(auth, new);
    if (auth->on_gtk_change)
        auth->on_gtk_change(auth, new->key, slot_install + 1, false);
    TRACE(TR_SECURITY, "sec: installed gtk=%s", tr_key(new->key, sizeof(new->key)));
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
    pktbuf_free(&supp->rt_buffer);
    pktbuf_init(&supp->rt_buffer, buf, buf_len);
    supp->rt_kmp_id = kmp_id;
    supp->rt_count  = 0;
    timer_start_rel(&auth->timer_group, &supp->rt_timer, supp->rt_timer.period_ms);
}

static void auth_rt_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_supp_ctx *supp = container_of(timer, struct auth_supp_ctx, rt_timer);
    struct auth_ctx *auth = container_of(group, struct auth_ctx, timer_group);

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
        timer_stop(group, timer);
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

static struct auth_supp_ctx *auth_get_supp(struct auth_ctx *auth, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp;

    SLIST_FIND(supp, &auth->supplicants, link, !memcmp(&supp->eui64, eui64, sizeof(supp->eui64)));
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
    supp->rt_timer.period_ms = auth->timeout_ms,
    supp->rt_timer.callback = auth_rt_timer_timeout;
    if (auth->radius_fd < 0)
        tls_init_client(&auth->tls, &supp->eap_tls.tls);
    SLIST_INSERT_HEAD(&auth->supplicants, supp, link);
    TRACE(TR_SECURITY, "sec: %-8s eui64=%s", "supp add", tr_eui64(supp->eui64.u8));
    return supp;
}

bool auth_get_supp_tk(struct auth_ctx *auth, const struct eui64 *eui64, uint8_t tk[16])
{
    struct auth_supp_ctx *supp = auth_get_supp(auth, eui64);

    if (!supp)
        return false;
    if (!memzcmp(supp->ptk, sizeof(supp->ptk)))
        return false;
    memcpy(tk, ieee80211_tk(supp->ptk), IEEE80211_AKM_1_TK_LEN_BYTES);
    return true;
}

void auth_send_eapol(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                     uint8_t kmp_id, const void *buf, size_t buf_len)
{
    const struct eapol_hdr *hdr;

    BUG_ON(buf_len < sizeof(*hdr));
    hdr = buf;
    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%u", "tx-eapol",
          val_to_str(hdr->packet_type, eapol_frames, "[UNK]"), be16toh(hdr->packet_body_length));
    auth->sendto_mac(auth, kmp_id, buf, buf_len, &supp->eui64);
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
        (kmp_id == IEEE802159_KMP_ID_80211_GKH && eapol_hdr->packet_type != EAPOL_PACKET_TYPE_KEY)) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet type %s for KMP ID %d", "eapol",
              val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), kmp_id);
        return;
    }

    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%d", "rx-eapol",
          val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"), ntohs(eapol_hdr->packet_body_length));

    supp = auth_fetch_supp(auth, eui64);

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
}

void auth_start(struct auth_ctx *auth, const struct eui64 *eui64)
{
    BUG_ON(auth->radius_fd >= 0);
    BUG_ON(!auth->sendto_mac);
    BUG_ON(!auth->cfg);

    if (auth->cfg->radius_addr.ss_family != AF_UNSPEC)
        radius_init(auth, (struct sockaddr *)&auth->cfg->radius_addr);
    else
        tls_init(&auth->tls, MBEDTLS_SSL_IS_SERVER, &auth->cfg->ca_cert, &auth->cfg->cert, &auth->cfg->key);

    SLIST_INIT(&auth->supplicants);
    timer_group_init(&auth->timer_group);
    auth->gtk_group.activation_timer.callback = auth_gtk_activation_timer_timeout;
    auth->gtk_group.install_timer.callback    = auth_gtk_install_timer_timeout;
    auth->eui64 = *eui64;
    auth->gtk_group.slot_active = 0;
    for (int i = 0; i < ARRAY_SIZE(auth->gtks); i++)
        auth->gtks[i].expiration_timer.callback = auth_gtk_expiration_timer_timeout;

    // Install the 1st key
    auth_gtk_install_timer_timeout(&auth->timer_group, &auth->gtk_group.install_timer);
    auth_gtk_activation_timer_start(auth, &auth->gtk_group);
}
