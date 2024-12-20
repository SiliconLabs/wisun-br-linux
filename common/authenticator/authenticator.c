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

#include "authenticator_key.h"

#include "authenticator.h"

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_EXPIRE_OFFSET: The expiration time of a GTK is calculated as the
 * expiration time of the GTK most recently installed at the Border Router
 * plus GTK_EXPIRE_OFFSET.
 */
static void auth_gtk_expiration_timer_start(struct auth_ctx *auth, struct ws_gtk *gtk, const struct ws_gtk *prev)
{
    const uint64_t start_ms = prev ? prev->expiration_timer.expire_ms : time_now_ms(CLOCK_MONOTONIC);
    const uint64_t expire_offset_ms = (uint64_t)auth->cfg->gtk_expire_offset_s * 1000;

    timer_start_abs(&auth->timer_group, &gtk->expiration_timer, start_ms + expire_offset_ms);
}

static void auth_gtk_expiration_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_ctx *ctx = container_of(group, struct auth_ctx, timer_group);
    struct ws_gtk *gtk = container_of(timer, struct ws_gtk, expiration_timer);

    if (ctx->on_gtk_change)
        ctx->on_gtk_change(ctx, NULL, gtk->slot + 1, false);
    TRACE(TR_SECURITY, "sec: expired gtk=%s", tr_key(gtk->gtk, sizeof(gtk->gtk)));
    memset(gtk->gtk, 0, sizeof(gtk->gtk));
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
 * GTK_NEW_ACTIVATION_TIME: The time at which the Border Router activates the
 * next GTK prior to expiration of the currently activated GTK. Expressed as a
 * fraction (1/X) of GTK_EXPIRE_OFFSET.
 */
static void auth_gtk_activation_timer_start(struct auth_ctx *auth, const struct ws_gtk *gtk)
{
    const uint64_t expire_offset_ms = (uint64_t)auth->cfg->gtk_expire_offset_s * 1000;
    const uint64_t expire_ms = gtk->expiration_timer.expire_ms;

    timer_start_abs(&auth->timer_group, &auth->gtk_activation_timer,
                    expire_ms - expire_offset_ms / auth->cfg->gtk_new_activation_time);
}

static void auth_gtk_activation_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_ctx *ctx = container_of(group, struct auth_ctx, timer_group);

    auth_gtk_activation_timer_start(ctx, &ctx->gtks[ctx->next_slot]);
    if (ctx->on_gtk_change)
        ctx->on_gtk_change(ctx, ctx->gtks[ctx->next_slot].gtk, ctx->next_slot + 1, true);
    ctx->cur_slot = ctx->next_slot;
    TRACE(TR_SECURITY, "sec: activated gtk=%s expiration=%"PRIu64" next_install=%"PRIu64" next_activation=%"PRIu64,
          tr_key(ctx->gtks[ctx->cur_slot].gtk, sizeof(ctx->gtks[ctx->cur_slot].gtk)),
          ctx->gtks[ctx->cur_slot].expiration_timer.expire_ms / 1000, ctx->gtk_install_timer.expire_ms / 1000,
          ctx->gtk_activation_timer.expire_ms / 1000);
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

    timer_start_abs(&auth->timer_group, &auth->gtk_install_timer,
                    start_ms + lifetime_ms * auth->cfg->gtk_new_install_required / 100);
}

static void auth_gtk_install_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_ctx *ctx = container_of(group, struct auth_ctx, timer_group);

    ctx->next_slot = (ctx->cur_slot + 1) % 4;
    rand_get_n_bytes_random(ctx->gtks[ctx->next_slot].gtk, sizeof(ctx->gtks[ctx->next_slot].gtk));
    auth_gtk_expiration_timer_start(ctx, &ctx->gtks[ctx->next_slot], &ctx->gtks[ctx->cur_slot]);
    auth_gtk_install_timer_start(ctx, &ctx->gtks[ctx->next_slot]);
    if (ctx->on_gtk_change)
        ctx->on_gtk_change(ctx, ctx->gtks[ctx->next_slot].gtk, ctx->next_slot + 1, false);
    TRACE(TR_SECURITY, "sec: installed gtk=%s", tr_key(ctx->gtks[ctx->next_slot].gtk, sizeof(ctx->gtks[ctx->next_slot].gtk)));
}

static void auth_rt_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct auth_supp_ctx *supp = container_of(timer, struct auth_supp_ctx, rt_timer);
    struct auth_ctx *ctx = container_of(group, struct auth_ctx, timer_group);

    supp->rt_count++;

    /*
     *     IEEE 802.11-2020 C.3 MIB detail
     * dot11RSNAConfigPairwiseUpdateCount [...] DEFVAL { 3 }
     */
    if (supp->rt_count == 3) {
        TRACE(TR_SECURITY, "sec: max retry count exceeded eui64=%s", tr_eui64(supp->eui64.u8));
        timer_stop(group, timer);
        return;
    }
    TRACE(TR_SECURITY, "sec: frame retry eui64=%s", tr_eui64(supp->eui64.u8));

    // Update replay counter and MIC on retry
    if (supp->rt_kmp_id == IEEE802159_KMP_ID_80211_4WH || supp->rt_kmp_id == IEEE802159_KMP_ID_80211_GKH)
        auth_key_refresh_rt_buffer(supp);

    auth_send_eapol(ctx, &supp->eui64, supp->rt_kmp_id, &supp->rt_buffer);
}

static struct auth_supp_ctx *auth_get_supp(struct auth_ctx *ctx, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp;

    SLIST_FIND(supp, &ctx->supplicants, link, !memcmp(&supp->eui64, eui64, sizeof(supp->eui64)));
    return supp;
}

static struct auth_supp_ctx *auth_fetch_supp(struct auth_ctx *ctx, const struct eui64 *eui64)
{
    struct auth_supp_ctx *supp = auth_get_supp(ctx, eui64);

    if (supp)
        return supp;

    supp = zalloc(sizeof(struct auth_supp_ctx));
    supp->eui64 = *eui64;
    supp->replay_counter = -1;
    supp->last_installed_key_slot = -1;
    supp->rt_timer.period_ms = 30 * 1000, // Arbitrary
    supp->rt_timer.callback = auth_rt_timer_timeout;
    SLIST_INSERT_HEAD(&ctx->supplicants, supp, link);
    TRACE(TR_SECURITY, "sec: %-8s eui64=%s", "supp add", tr_eui64(supp->eui64.u8));
    return supp;
}

void auth_set_supp_pmk(struct auth_ctx *ctx, const struct eui64 *eui64, const uint8_t pmk[32])
{
    struct auth_supp_ctx *supp = auth_fetch_supp(ctx, eui64);

    memcpy(supp->pmk, pmk, sizeof(supp->pmk));
    supp->pmk_expiration_s = UINT64_MAX; // Infinite lifetime
}

bool auth_get_supp_tk(struct auth_ctx *ctx, const struct eui64 *eui64, uint8_t tk[16])
{
    struct auth_supp_ctx *supp = auth_get_supp(ctx, eui64);

    if (!supp)
        return false;
    if (!memzcmp(supp->ptk, sizeof(supp->ptk)))
        return false;
    memcpy(tk, supp->ptk + IEEE80211_AKM_1_KCK_LEN_BYTES + IEEE80211_AKM_1_KEK_LEN_BYTES, IEEE80211_AKM_1_TK_LEN_BYTES);
    return true;
}

void auth_send_eapol(struct auth_ctx *ctx, const struct eui64 *dst, uint8_t kmp_id, struct pktbuf *buf)
{
    uint8_t packet_type = *(pktbuf_head(buf) + offsetof(struct eapol_hdr, packet_type));

    TRACE(TR_SECURITY, "sec: %-8s type=%s length=%zu", "tx-eapol",
          val_to_str(packet_type, eapol_frames, "[UNK]"), pktbuf_len(buf));
    ctx->sendto_mac(ctx, kmp_id, pktbuf_head(buf), pktbuf_len(buf), dst);
}

void auth_recv_eapol(struct auth_ctx *ctx, uint8_t kmp_id, const struct eui64 *eui64,
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

    supp = auth_fetch_supp(ctx, eui64);

    switch (eapol_hdr->packet_type) {
    case EAPOL_PACKET_TYPE_KEY:
        auth_key_recv(ctx, supp, &iobuf);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported eapol packet type %d", "eapol", eapol_hdr->packet_type);
        break;
    }
}

void auth_start(struct auth_ctx *ctx, const struct eui64 *eui64)
{
    BUG_ON(!ctx->sendto_mac);
    BUG_ON(!ctx->cfg);

    SLIST_INIT(&ctx->supplicants);
    timer_group_init(&ctx->timer_group);
    ctx->gtk_activation_timer.callback = auth_gtk_activation_timer_timeout;
    ctx->gtk_install_timer.callback    = auth_gtk_install_timer_timeout;
    ctx->eui64 = *eui64;
    ctx->cur_slot = 0;
    for (int i = 0; i < ARRAY_SIZE(ctx->gtks); i++) {
        ctx->gtks[i].expiration_timer.callback = auth_gtk_expiration_timer_timeout;
        ctx->gtks[i].slot = i;
    }

    // We assume the gtkhash of the generated gtk won't be full of zeros
    rand_get_n_bytes_random(ctx->gtks[ctx->cur_slot].gtk, sizeof(ctx->gtks[ctx->cur_slot].gtk));
    auth_gtk_expiration_timer_start(ctx, &ctx->gtks[ctx->cur_slot], NULL);
    auth_gtk_install_timer_start(ctx, &ctx->gtks[ctx->cur_slot]);
    auth_gtk_activation_timer_start(ctx, &ctx->gtks[ctx->cur_slot]);
    if (ctx->on_gtk_change)
        ctx->on_gtk_change(ctx, ctx->gtks[ctx->cur_slot].gtk, 1, true);
    TRACE(TR_SECURITY, "sec: authenticator started gtk=%s expiration=%"PRIu64" next_install=%"PRIu64
          " next_activation=%"PRIu64, tr_key(ctx->gtks[ctx->cur_slot].gtk, sizeof(ctx->gtks[ctx->cur_slot].gtk)),
          ctx->gtks[ctx->cur_slot].expiration_timer.expire_ms / 1000, ctx->gtk_install_timer.expire_ms / 1000,
          ctx->gtk_activation_timer.expire_ms / 1000);
}
