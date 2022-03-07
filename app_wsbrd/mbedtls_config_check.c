/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <mbedtls/build_info.h>
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>

#include "common/log.h"
#include "common/utils.h"

#include "mbedtls_config_check.h"

// Compilation check
#if !defined(MBEDTLS_SSL_TLS_C)                        || \
    !defined(MBEDTLS_SSL_SRV_C)                        || \
    !defined(MBEDTLS_SSL_CLI_C)                        || \
    !defined(MBEDTLS_SSL_EXPORT_KEYS)                  || \
    !defined(MBEDTLS_X509_CRL_PARSE_C)                 || \
    !defined(MBEDTLS_PEM_PARSE_C)                      || \
    !defined(MBEDTLS_NIST_KW_C)                        || \
    !defined(MBEDTLS_CTR_DRBG_C)                       || \
    !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)         || \
    !defined(MBEDTLS_CCM_C)

#error "Incompatible mbedTLS"
#endif

// Runtime check
void wsbr_check_mbedtls_features()
{
    static const char *features[] = {
        "MBEDTLS_SSL_TLS_C",
        "MBEDTLS_SSL_SRV_C",
        "MBEDTLS_SSL_CLI_C",
        "MBEDTLS_SSL_EXPORT_KEYS",
        "MBEDTLS_X509_CRL_PARSE_C",
        "MBEDTLS_PEM_PARSE_C",
        "MBEDTLS_NIST_KW_C",
        "MBEDTLS_CTR_DRBG_C",
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(features); i++)
        if (mbedtls_version_check_feature(features[i]))
            FATAL(1, "MbedTLS is not compiled with %s", features[i]);
    if (mbedtls_version_get_number() < 3000000)
        if (mbedtls_version_check_feature("MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE");
    if (!mbedtls_ssl_get_ciphersuite_id("TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
    if (!mbedtls_ecp_curve_info_from_name("secp256r1"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_ECP_DP_SECP256R1_ENABLED");
}
