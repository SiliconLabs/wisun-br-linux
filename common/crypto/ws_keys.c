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
#include <string.h>

#include <mbedtls/sha256.h>

#include "common/crypto/hmac_md.h"
#include "common/log.h"

//   Wi-SUN FAN 1.1v08 6.5.4.1.1 Group AES Key (GAK)
// GAK = Truncate-128(SHA-256(Network Name || L/GTK[X])
void ws_generate_gak(const char *netname, const uint8_t gtk[16], uint8_t gak[16])
{
    mbedtls_sha256_context ctx;
    uint8_t hash[32];
    int ret;

    mbedtls_sha256_init(&ctx);
    ret = mbedtls_sha256_starts(&ctx, 0);
    FATAL_ON(ret < 0, 2, "%s: mbedtls_sha256_starts: %s", __func__, tr_mbedtls_err(ret));
    ret = mbedtls_sha256_update(&ctx, (void *)netname, strlen(netname));
    FATAL_ON(ret < 0, 2, "%s: mbedtls_sha256_update: %s", __func__, tr_mbedtls_err(ret));
    ret = mbedtls_sha256_update(&ctx, gtk, 16);
    FATAL_ON(ret < 0, 2, "%s: mbedtls_sha256_update: %s", __func__, tr_mbedtls_err(ret));
    ret = mbedtls_sha256_finish(&ctx, hash);
    FATAL_ON(ret < 0, 2, "%s: mbedtls_sha256_finish: %s", __func__, tr_mbedtls_err(ret));
    mbedtls_sha256_free(&ctx);
    memcpy(gak, hash, 16);
}

/*
 *   Wi-SUN FAN 1.1v08 6.3.2.2.2 Pairwise Transient Key ID KDE (PTKID)
 *  PTKID = HMAC-SHA1-128(PTK, "PTK Name" || AA || SPA)
 */
void ws_derive_ptkid(const uint8_t ptk[48], const uint8_t auth_eui64[8], const uint8_t supp_eui64[8],
                     uint8_t ptkid[16])
{
    struct {
        uint8_t pmk_name[8];
        uint8_t auth_eui64[8];
        uint8_t supp_eui64[8];
    } data = {
        .pmk_name = "PTK Name",
    };
    int ret;

    memcpy(data.auth_eui64, auth_eui64, sizeof(data.auth_eui64));
    memcpy(data.supp_eui64, supp_eui64, sizeof(data.supp_eui64));
    ret = hmac_md_sha1(ptk, 48, (const uint8_t *)&data, sizeof(data), ptkid, 16);
    FATAL_ON(ret, 2, "%s: hmac_md_sha1: %s", __func__, strerror(-ret));
}
