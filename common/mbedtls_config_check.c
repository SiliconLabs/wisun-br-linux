/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include "common/log.h"
#include "common/memutils.h"

#include "mbedtls_config_check.h"

// Compilation check
#if !defined(MBEDTLS_SSL_TLS_C)                        || \
    !defined(MBEDTLS_SSL_SRV_C)                        || \
    !defined(MBEDTLS_SSL_CLI_C)                        || \
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
void check_mbedtls_features()
{
    static const char *features[] = {
        "MBEDTLS_SSL_TLS_C",
        "MBEDTLS_SSL_SRV_C",
        "MBEDTLS_SSL_CLI_C",
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
    if (mbedtls_version_get_number() < 3010000)
        if (mbedtls_version_check_feature("MBEDTLS_SSL_EXPORT_KEYS"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_SSL_EXPORT_KEYS");
    if (!mbedtls_ssl_get_ciphersuite_id("TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
    if (!mbedtls_ecp_curve_info_from_name("secp256r1"))
            FATAL(1, "MbedTLS is not compiled with %s", "MBEDTLS_ECP_DP_SECP256R1_ENABLED");
}
