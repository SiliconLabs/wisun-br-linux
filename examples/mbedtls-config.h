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
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// The keys use NIST P-256 Elliptic Curve and the certificates are signed using
// ecdsa-with-SHA256.
//
// Then during authentication, TLS version is 1.2 or later is required and
// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 is the only cipher suite supported.
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_EXPORT_KEYS
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_CCM_C

#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_MD_C

#define MBEDTLS_NIST_KW_C
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C

#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

// Certificates are encoded using PEM format
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

// For Radius client
#define MBEDTLS_MD5_C

// Needed for entropy
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

// Allow to check mbedTLS features during runtime
#define MBEDTLS_VERSION_FEATURES
#define MBEDTLS_VERSION_C

// Not mandatory, but recommended
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_RESTARTABLE
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_HMAC_DRBG_C

// Help to find errors
#define MBEDTLS_ERROR_C
#define MBEDTLS_DEPRECATED_WARNING
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

// Only used with mbedTLS 2.x
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_REMOVE_3DES_CIPHERSUITES
#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
#define MBEDTLS_ECDH_LEGACY_CONTEXT

#endif
