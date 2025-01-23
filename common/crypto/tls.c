/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)
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

#define _GNU_SOURCE
#include <mbedtls/debug.h>

#include "common/time_extra.h"
#include "common/mathutils.h"
#include "common/log.h"

#include "tls.h"

int tls_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct tls_io *tls_io = ctx;

    pktbuf_push_tail(&tls_io->tx, buf, len);
    return len;
}

int tls_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret = MBEDTLS_ERR_SSL_WANT_READ;
    struct tls_io *tls_io = ctx;

    if (!pktbuf_len(&tls_io->rx))
        return ret;

    ret = MIN(pktbuf_len(&tls_io->rx), len);
    pktbuf_pop_head(&tls_io->rx, buf, ret);

    if (!pktbuf_len(&tls_io->rx))
        pktbuf_free(&tls_io->rx);
    return ret;
}

void tls_install_pmk(struct tls_client_ctx *tls_client, const uint8_t key[32])
{
    // Prevent Key Reinstallation Attacks (https://www.krackattacks.com)
    if (!memcmp(tls_client->pmk.key, key, sizeof(tls_client->pmk.key))) {
        WARN("sec: ignore reinstallation of pmk");
        return;
    }

    memcpy(tls_client->pmk.key, key, sizeof(tls_client->pmk.key));
    tls_client->pmk.installation_s = time_now_s(CLOCK_MONOTONIC);

    /*
     *     IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter. This field is represented as an unsigned integer,
     *    and is initialized to 0 when the PMK is established.
     */
    tls_client->pmk.replay_counter = 0;

    // Reset PTK to prevent replay of EAPoL-Key frames with the old PTK.
    memset(&tls_client->ptk, 0, sizeof(tls_client->ptk));

    TRACE(TR_SECURITY, "sec: pmk installed");
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
static void tls_export_keys(void *ctx, mbedtls_ssl_key_export_type type,
                            const unsigned char *secret, size_t secret_len,
                            const unsigned char client_random[32],
                            const unsigned char server_random[32],
                            mbedtls_tls_prf_types tls_prf_type)
{
    struct tls_client_ctx *tls_client = ctx;
    uint8_t derived_key[128];
    uint8_t random[64];
    int ret;

    memcpy(random, client_random, 32);
    memcpy(random + 32, server_random, 32);

    ret = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len, "client EAP encryption", random, sizeof(random),
                              derived_key, sizeof(derived_key));
    FATAL_ON(ret, 2, "%s: mbedtls_ssl_tls_prf: %s", __func__, tr_mbedtls_err(ret));

    tls_install_pmk(tls_client, derived_key);
}

void tls_init_client(struct tls_ctx *tls, struct tls_client_ctx *tls_client)
{
    int ret;

    mbedtls_ssl_init(&tls_client->ssl_ctx);
    ret = mbedtls_ssl_setup(&tls_client->ssl_ctx, &tls->ssl_config);
    BUG_ON(ret);

    mbedtls_ssl_set_bio(&tls_client->ssl_ctx, &tls_client->io, tls_send, tls_recv, NULL);
    mbedtls_ssl_set_export_keys_cb(&tls_client->ssl_ctx, tls_export_keys, tls_client);
}

static void tls_debug(void *ctx, int level, const char *file, int line, const char *string)
{
    TRACE(TR_MBEDTLS, "%i %s %i %s", level, file, line, string);
}

void tls_init(struct tls_ctx *tls, int endpoint, const struct iovec *ca_cert, const struct iovec *cert,
              const struct iovec *key)
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

    mbedtls_x509_crt_init(&tls->ca_cert);
    mbedtls_x509_crt_init(&tls->cert);
    mbedtls_pk_init(&tls->key);
    ret = mbedtls_x509_crt_parse(&tls->ca_cert, ca_cert->iov_base, ca_cert->iov_len);
    FATAL_ON(ret, 1, "mbedtls_x509_crt_parse: cannot parse CA certificate");
    ret = mbedtls_x509_crt_parse(&tls->cert, cert->iov_base, cert->iov_len);
    FATAL_ON(ret, 1, "mbedtls_x509_crt_parse: cannot parse own certificate");
    ret = mbedtls_pk_parse_key(&tls->key, key->iov_base, key->iov_len, NULL, 0,
                               mbedtls_ctr_drbg_random, &tls->ctr_drbg);
    FATAL_ON(ret, 1, "mbedtls_pk_parse_key: cannot parse private key");

    mbedtls_ssl_config_init(&tls->ssl_config);
    ret = mbedtls_ssl_config_defaults(&tls->ssl_config, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    BUG_ON(ret);

    mbedtls_entropy_init(&tls->entropy);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&tls->ctr_drbg , mbedtls_entropy_func, &tls->entropy, NULL, 0);
    BUG_ON(ret);
    mbedtls_ssl_conf_rng(&tls->ssl_config, mbedtls_ctr_drbg_random, &tls->ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(&tls->ssl_config, &tls->cert, &tls->key);
    BUG_ON(ret);
    mbedtls_ssl_conf_cert_profile(&tls->ssl_config, &certificate_profile);
    mbedtls_ssl_conf_ca_chain(&tls->ssl_config, &tls->ca_cert, NULL);
    mbedtls_ssl_conf_authmode(&tls->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_conf_ciphersuites(&tls->ssl_config, tls_ciphersuites);
#if MBEDTLS_VERSION_NUMBER < 0x03010000
    mbedtls_ssl_conf_curves(&tls->ssl_config, tls_curves);
#else
    mbedtls_ssl_conf_groups(&tls->ssl_config, tls_curves);
#endif
#if MBEDTLS_VERSION_NUMBER < 0x03020000
    mbedtls_ssl_conf_sig_hashes(&tls->ssl_config, tls_sig_hashes);
#else
    mbedtls_ssl_conf_sig_algs(&tls->ssl_config, tls_sig_hashes);
#endif

    if (g_enabled_traces & TR_MBEDTLS) {
        mbedtls_ssl_conf_dbg(&tls->ssl_config, tls_debug, NULL);
        mbedtls_debug_set_threshold(4);
    }

    // TLS v1.2 only
    mbedtls_ssl_conf_min_version(&tls->ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&tls->ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
}
