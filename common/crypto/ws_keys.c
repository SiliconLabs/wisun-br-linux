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

#include "common/log.h"
#include "common/mbedtls_extra.h"

#include "ws_keys.h"

void ws_gtk_clear(struct timer_group *group, struct ws_gtk *gtk)
{
    memset(gtk->key, 0, sizeof(gtk->key));
    gtk->frame_counter = 0;
    timer_stop(group, &gtk->expiration_timer);
}

//   Wi-SUN FAN 1.1v08 6.5.4.1.1 Group AES Key (GAK)
// GAK = Truncate-128(SHA-256(Network Name || L/GTK[X])
void ws_generate_gak(const char *netname, const uint8_t gtk[16], uint8_t gak[16])
{
    mbedtls_sha256_context ctx;
    uint8_t hash[32];

    mbedtls_sha256_init(&ctx);
    xmbedtls_sha256_starts(&ctx, 0);
    xmbedtls_sha256_update(&ctx, (void *)netname, strlen(netname));
    xmbedtls_sha256_update(&ctx, gtk, 16);
    xmbedtls_sha256_finish(&ctx, hash);
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
    static const char *label = "PTK Name";
    mbedtls_md_context_t md;
    uint8_t hmac[20];

    mbedtls_md_init(&md);
    xmbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    xmbedtls_md_hmac_starts(&md, ptk, 48);
    xmbedtls_md_hmac_update(&md, (const uint8_t *)label, strlen(label));
    xmbedtls_md_hmac_update(&md, auth_eui64, 8);
    xmbedtls_md_hmac_update(&md, supp_eui64, 8);
    xmbedtls_md_hmac_finish(&md, hmac);
    mbedtls_md_free(&md);
    memcpy(ptkid, hmac, 16);
}
