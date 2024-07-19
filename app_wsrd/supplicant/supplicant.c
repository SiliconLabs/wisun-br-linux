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
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/eapol.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/kde.h"

#include "supplicant_eap.h"
#include "supplicant_key.h"

#include "supplicant.h"

static int supp_mbedtls_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct supplicant_ctx *supp = ctx;

    pktbuf_push_tail(&supp->tx_buffer, buf, len);
    return len;
}

static int supp_mbedtls_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret = MBEDTLS_ERR_SSL_WANT_READ;
    struct supplicant_ctx *supp = ctx;

    if (!pktbuf_len(&supp->rx_buffer))
        return ret;

    ret = MIN(pktbuf_len(&supp->rx_buffer), len);
    pktbuf_pop_head(&supp->rx_buffer, buf, ret);

    if (!pktbuf_len(&supp->rx_buffer))
        pktbuf_free(&supp->rx_buffer);
    return ret;
}

/*
 *   RFC5216 - 2.3. Key Hierarchy
 * Key_Material = TLS-PRF-128(master_secret, "client EAP encryption",
 *                            client.random || server.random)
 * MSK          = Key_Material(0,63)
 * Enc-RECV-Key = MSK(0,31) = Peer to Authenticator Encryption Key
 *                (MS-MPPE-Recv-Key in [RFC2548]).  Also known as the
 *                PMK in [IEEE-802.11].
 */
static void supp_mbedtls_export_keys(void *p_expkey, mbedtls_ssl_key_export_type type, const unsigned char *secret,
                                     size_t secret_len, const unsigned char client_random[32],
                                     const unsigned char server_random[32], mbedtls_tls_prf_types tls_prf_type)
{
    struct supplicant_ctx *supp = p_expkey;
    uint8_t derived_key[128];
    uint8_t random[64];
    int ret;

    memcpy(random, client_random, 32);
    memcpy(random + 32, server_random, 32);

    ret = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len, "client EAP encryption", random, sizeof(random),
                              derived_key, sizeof(derived_key));
    FATAL_ON(ret, 2, "%s: mbedtls_ssl_tls_prf: %s", __func__, tr_mbedtls_err(ret));

    memcpy(supp->pmk, derived_key, sizeof(supp->pmk));

    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter. This field is represented as an unsigned integer,
     * and is initialized to 0 when the PMK is established.
     *
     * [...]
     *
     * The Supplicant should also use the key replay counter and ignore
     * EAPOL-Key frames with a Key Replay Counter field value smaller than or
     * equal to any received in a valid message. The local Key Replay Counter
     * field should not be updated until after the EAPOL-Key MIC is checked and
     * is found to be valid. In other words, the Supplicant never updates the
     * Key Replay Counter field for message 1 in the 4-way handshake, as it
     * includes no MIC.
     *
     * Note: setting this variable to -1 will ensure we allow message 1 and
     * potential retransmissions.
     */
    supp->replay_counter = -1;
}

static void supp_mbedtls_debug(void *ctx, int level, const char *file, int line, const char *string)
{
    TRACE(TR_MBEDTLS, "%i %s %i %s", level, file, line, string);
}

void supp_send_eapol(struct supplicant_ctx *supp, uint8_t kmp_id, struct pktbuf *buf)
{
    uint8_t packet_type = *(pktbuf_head(buf) + offsetof(struct eapol_hdr, packet_type));
    uint8_t *dst = supp->get_target(supp);

    if (!memcmp(dst, ieee802154_addr_bc, sizeof(ieee802154_addr_bc))) {
        TRACE(TR_DROP, "drop %-9s: no eapol target available", "eapol");
        return;
    }

    TRACE(TR_SECURITY, "tx-eapol type=%s length=%lu dst=%s", val_to_str(packet_type, eapol_frames, "[UNK]"),
          pktbuf_len(buf), tr_eui64(dst));
    supp->sendto_mac(supp, kmp_id, pktbuf_head(buf), pktbuf_len(buf), dst);
}

static void supp_failure_key_request(struct rfc8415_txalg *txalg)
{
    struct supplicant_ctx *supp = container_of(txalg, struct supplicant_ctx, key_request_txalg);

    TRACE(TR_SECURITY, "sec: no valid response to key request after %d retries", supp->key_request_txalg.mrc);
    supp->on_failure(supp);
}

static void supp_timeout_key_request(struct rfc8415_txalg *txalg)
{
    struct eapol_key_frame frame = {
        .descriptor_type = EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE,
        .information = htobe16(FIELD_PREP(IEEE80211_MASK_KEY_INFO_VERSION, IEEE80211_KEY_INFO_VERSION) |
                               FIELD_PREP(IEEE80211_MASK_KEY_INFO_REQ, true)),
    };
    struct supplicant_ctx *supp = container_of(txalg, struct supplicant_ctx, key_request_txalg);
    struct pktbuf buf = { };
    uint8_t pmkid[16];
    uint8_t ptkid[16];
    uint8_t lgtkl = 0;
    uint8_t gtkl = 0;

    ieee80211_derive_pmkid(supp->pmk, supp->authenticator_eui64, supp->eui64, pmkid);
    ws_derive_ptkid(supp->ptk, supp->authenticator_eui64, supp->eui64, ptkid);

    for (int i = 0; i < 4; i++)
        if (!timer_stopped(&supp->gtks[i].expiration_timer))
            gtkl |= BIT(i);
    for (int i = 4; i < ARRAY_SIZE(supp->gtks); i++)
        if (!timer_stopped(&supp->gtks[i].expiration_timer))
            lgtkl |= BIT(i - 4);

    if (memzcmp(supp->pmk, sizeof(supp->pmk)))
        kde_write_pmkid(&buf, pmkid);
    if (memzcmp(supp->ptk, sizeof(supp->ptk)))
        kde_write_ptkid(&buf, ptkid);
    kde_write_gtkl(&buf, gtkl);
    kde_write_lgtkl(&buf, lgtkl);
    kde_write_nr(&buf, WS_NR_ROLE_ROUTER);
    frame.data_length = htobe16(pktbuf_len(&buf));
    pktbuf_push_head(&buf, &frame, sizeof(frame));
    eapol_write_hdr_head(&buf, EAPOL_PACKET_TYPE_KEY);
    supp_send_eapol(supp, IEEE802159_KMP_ID_8021X, &buf);
    pktbuf_free(&buf);
}

void supp_on_eap_success(struct supplicant_ctx *supp)
{
    timer_stop(NULL, &supp->failure_timer);
    /*
     * Wi-SUN does not specify any timeout between EAP-Success and 4WH message 1.
     * 60 seconds is an arbitrary value.
     */
    timer_start_rel(NULL, &supp->failure_timer, 60 * 1000);
}

static void supp_failure_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct supplicant_ctx *supp = container_of(timer, struct supplicant_ctx, failure_timer);

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

void supp_recv_eapol(struct supplicant_ctx *supp, uint8_t kmp_id, const uint8_t *buf, size_t buf_len,
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

    eapol_hdr = (const struct eapol_hdr *)iobuf_pop_data_ptr(&iobuf, sizeof(struct eapol_hdr));
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

    TRACE(TR_SECURITY, "rx-eapol type=%s length=%d", val_to_str(eapol_hdr->packet_type, eapol_frames, "[UNK]"),
          ntohs(eapol_hdr->packet_body_length));

    if (authenticator_eui64)
        memcpy(supp->authenticator_eui64, authenticator_eui64, sizeof(supp->authenticator_eui64));

    /*
     *   RFC3748 - 4.2. Success and Failure
     * Because the Success and Failure packets are not
     * acknowledged, they are not retransmitted by the authenticator, and
     * may be potentially lost. A peer MUST allow for this circumstance as
     * described in this note.
     */
    if (mbedtls_ssl_is_handshake_over(&supp->ssl_ctx) &&
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
    struct ws_gtk *gtk = container_of(timer, struct ws_gtk, expiration_timer);
    struct supplicant_ctx *supp = container_of((const struct ws_gtk (*)[7])(gtk - gtk->slot), struct supplicant_ctx, gtks);

    TRACE(TR_SECURITY, "sec: gtk[%u] expired", gtk->slot + 1);
    supp->on_gtk_change(supp, NULL, gtk->slot + 1);
}

bool supp_has_gtk(struct supplicant_ctx *supp, uint8_t gtkhash[8], uint8_t gtkhash_index)
{
    uint8_t hash[32] = { };
    bool has_gtk;
    int ret;

    if (!supp->running)
        return false;

    if (timer_stopped(&supp->gtks[gtkhash_index - 1].expiration_timer)) {
        has_gtk = !memzcmp(gtkhash, 8);
    } else {
        ret = mbedtls_sha256(supp->gtks[gtkhash_index - 1].gtk, 16, hash, 0);
        FATAL_ON(ret, 2, "%s: mbedtls_sha256: %s", __func__, tr_mbedtls_err(ret));
        has_gtk = !memcmp(hash + 24, gtkhash, 8);
    }
    if (!has_gtk)
        TRACE(TR_SECURITY, "sec: gtkhash[%u] mismatch got:%s expected:%s", gtkhash_index,
              tr_key(hash + 24, 8), tr_key(gtkhash, 8));
    return has_gtk;
}

void supp_start_key_request(struct supplicant_ctx *supp)
{
    if (!supp->running)
        return;
    if (!rfc8415_txalg_stopped(&supp->key_request_txalg) || !timer_stopped(&supp->failure_timer))
        return;
    rfc8415_txalg_start(&supp->key_request_txalg);
    TRACE(TR_SECURITY, "eapol-key tx=%"PRIu64"ms",
          supp->key_request_txalg.timer_delay.expire_ms - time_now_ms(CLOCK_MONOTONIC));
}

void supp_stop(struct supplicant_ctx *supp)
{
    rfc8415_txalg_stop(&supp->key_request_txalg);
    timer_stop(NULL, &supp->failure_timer);
    supp->running = false;
    TRACE(TR_SECURITY, "supplicant stopped");
}

void supp_start(struct supplicant_ctx *supp)
{
    BUG_ON(supp->running);
    supp->running = true;
    supp->last_tx_eap_type = EAP_TYPE_NAK;
    supp->last_eap_identifier = -1;
    supp->eap_tls_start_received = false;
    pktbuf_init(&supp->tx_buffer, NULL, 0);
    pktbuf_init(&supp->rx_buffer, NULL, 0);
    pktbuf_init(&supp->rt_buffer, NULL, 0);
    supp->expected_rx_len = 0;
    supp->fragment_id = 0;
    mbedtls_ssl_session_reset(&supp->ssl_ctx);
    supp->replay_counter = -1;
    supp_start_key_request(supp);
    TRACE(TR_SECURITY, "supplicant started");
}

void supp_init(struct supplicant_ctx *supp, struct iovec *ca_cert, struct iovec *cert, struct iovec *key,
               const uint8_t eui64[8])
{
    /*
     * Note: mbedtls expects the given configuration variables to always be
     * accessible at the given address.
     * Therefore, these variables must remain static.
     */
    static const mbedtls_x509_crt_profile certificate_profile = {
        .allowed_mds    = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
        .allowed_pks    = MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA) | MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECKEY),
        .allowed_curves = MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1),
        .rsa_min_bitlen = 0,
    };
    /*
     *   Wi-SUN FAN 1.1v08 - 6.5.2.1 EAPOL Over 802.15.4
     * FAN nodes MUST support the EAP-TLS method with the
     * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 cipher suite [RFC7251].
     */
    static const int tls_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        0,
    };
    /*
     *   Wi-SUN FAN 1.1v08 - 6.5.1 Public Key Infrastructure
     * All Wi-SUN certificates (device, root, and intermediate CA) must contain
     * only an EC P-256 public key in uncompressed format.
     */
#if MBEDTLS_VERSION_NUMBER < 0x03010000
    static const mbedtls_ecp_group_id tls_curves[] = {
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_ECP_DP_NONE,
    };
#else
    static const uint16_t tls_curves[] = {
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
        MBEDTLS_SSL_IANA_TLS_GROUP_NONE,
    };
#endif
    /*
     *   Wi-SUN FAN 1.1v08 - 6.5.1 Public Key Infrastructure
     * All Wi-SUN certificates MUST only be signed with SHA256withECDSA.
     */
#if MBEDTLS_VERSION_NUMBER < 0x03020000
    static const int tls_sig_hashes[] = {
        MBEDTLS_MD_SHA256,
        MBEDTLS_MD_NONE,
    };
#else
    static const uint16_t tls_sig_hashes[] = {
        (MBEDTLS_SSL_HASH_SHA256 << 8) | MBEDTLS_SSL_SIG_ECDSA,
        MBEDTLS_TLS1_3_SIG_NONE,
    };
#endif
    int ret;

    BUG_ON(!supp->sendto_mac);
    BUG_ON(!supp->get_target);
    BUG_ON(!supp->on_gtk_change);
    BUG_ON(!supp->on_failure);

    supp->failure_timer.callback = supp_failure_timer_timeout;
    supp->key_request_txalg.tx = supp_timeout_key_request;
    supp->key_request_txalg.fail = supp_failure_key_request;
    for (int i = 0; i < ARRAY_SIZE(supp->gtks); i++) {
        supp->gtks[i].expiration_timer.callback = supp_gtk_expiration_timer_timeout;
        supp->gtks[i].slot = i;
    }
    rfc8415_txalg_init(&supp->key_request_txalg);
    memcpy(supp->eui64, eui64, sizeof(supp->eui64));

    mbedtls_ssl_init(&supp->ssl_ctx);
    mbedtls_ssl_config_init(&supp->ssl_config);
    ret = mbedtls_ssl_config_defaults(&supp->ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    BUG_ON(ret);

    mbedtls_x509_crt_init(&supp->ca_cert);
    mbedtls_x509_crt_init(&supp->cert);
    mbedtls_pk_init(&supp->key);

    mbedtls_entropy_init(&supp->entropy);
    mbedtls_ctr_drbg_init(&supp->ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&supp->ctr_drbg , mbedtls_entropy_func, &supp->entropy, NULL, 0);
    BUG_ON(ret);
    mbedtls_ssl_conf_rng(&supp->ssl_config, mbedtls_ctr_drbg_random, &supp->ctr_drbg);

    ret = mbedtls_x509_crt_parse(&supp->ca_cert, ca_cert->iov_base, ca_cert->iov_len);
    FATAL_ON(ret, 1, "mbedtls_x509_crt_parse: cannot parse CA certificate");
    ret = mbedtls_x509_crt_parse(&supp->cert, cert->iov_base, cert->iov_len);
    FATAL_ON(ret, 1, "mbedtls_x509_crt_parse: cannot parse own certificate");
    ret = mbedtls_pk_parse_key(&supp->key, key->iov_base, key->iov_len, NULL, 0,
                               mbedtls_ctr_drbg_random, &supp->ctr_drbg);
    FATAL_ON(ret, 1, "mbedtls_pk_parse_key: cannot parse private key");

    ret = mbedtls_ssl_conf_own_cert(&supp->ssl_config, &supp->cert, &supp->key);
    BUG_ON(ret);
    mbedtls_ssl_conf_cert_profile(&supp->ssl_config, &certificate_profile);
    mbedtls_ssl_conf_ca_chain(&supp->ssl_config, &supp->ca_cert, NULL);

    mbedtls_ssl_conf_ciphersuites(&supp->ssl_config, tls_ciphersuites);
#if MBEDTLS_VERSION_NUMBER < 0x03010000
    mbedtls_ssl_conf_curves(&supp->ssl_config, tls_curves);
#else
    mbedtls_ssl_conf_groups(&supp->ssl_config, tls_curves);
#endif
#if MBEDTLS_VERSION_NUMBER < 0x03020000
    mbedtls_ssl_conf_sig_hashes(&supp->ssl_config, tls_sig_hashes);
#else
    mbedtls_ssl_conf_sig_algs(&supp->ssl_config, tls_sig_hashes);
#endif

    if (g_enabled_traces & TR_MBEDTLS) {
        mbedtls_ssl_conf_dbg(&supp->ssl_config, supp_mbedtls_debug, NULL);
        mbedtls_debug_set_threshold(4);
    }

    // TLS v1.2 only
    mbedtls_ssl_conf_min_version(&supp->ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&supp->ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    ret = mbedtls_ssl_setup(&supp->ssl_ctx, &supp->ssl_config);
    BUG_ON(ret);

    mbedtls_ssl_set_bio(&supp->ssl_ctx, supp, supp_mbedtls_send, supp_mbedtls_recv, NULL);
    mbedtls_ssl_set_export_keys_cb(&supp->ssl_ctx, supp_mbedtls_export_keys, supp);
}
