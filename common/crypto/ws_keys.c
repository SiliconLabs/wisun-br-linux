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
#include <fnmatch.h>
#include <string.h>

#include "common/log.h"
#include "common/mathutils.h"
#include "common/mbedtls_extra.h"
#include "common/key_value_storage.h"
#include "common/bits.h"

#include "ws_keys.h"

// GTK Liveness: BIT(i) is 1 if gtks[i] is live, 0 if gtks[i] is expired
uint8_t ws_gtkl(const struct ws_gtk *gtks, int count)
{
    uint8_t gtkl = 0;

    for (int i = 0; i < count; i++)
        if (ws_gtk_installed(&gtks[i]))
            gtkl |= BIT(i);
    return gtkl;
}

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

#define WS_GTK_COUNTER_FILENAME_LEN 32 // counter-xx:xx:xx:xx:xx:xx:xx:xx

static void ws_gtk_counter_filename(const uint8_t gtk[16],
                                    char filename[WS_GTK_COUNTER_FILENAME_LEN])
{
    uint8_t hash[32];

    xmbedtls_sha256(gtk, 16, hash, false);
    strcpy(filename, "counter-");
    str_bytes(hash + 24, 8, NULL, filename + strlen(filename),
              WS_GTK_COUNTER_FILENAME_LEN - strlen(filename), DELIM_COLON);
}

void ws_gtk_counter_load(struct ws_gtk *gtk)
{
    char filename[WS_GTK_COUNTER_FILENAME_LEN];
    struct storage_parse_info *info;

    gtk->frame_counter = 0;

    ws_gtk_counter_filename(gtk->key, filename);
    info = storage_open_prefix(filename, "r");
    if (!info)
        return;

    while (storage_parse_line(info) != EOF) {
        if (!fnmatch("frame_counter", info->key, 0))
            gtk->frame_counter = add32sat(strtoul(info->value, NULL, 0),
                                          WS_GTK_COUNTER_INC);
        else
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
    }

    storage_close(info);
}

void ws_gtk_counter_store(const struct ws_gtk *gtk)
{
    char filename[WS_GTK_COUNTER_FILENAME_LEN];
    struct storage_parse_info *info;

    ws_gtk_counter_filename(gtk->key, filename);
    info = storage_open_prefix(filename, "w");
    if (!info)
        return;

    fprintf(info->file, "frame_counter = %u\n", gtk->frame_counter);

    storage_close_flush(info);
}

void ws_gtk_counter_del(const struct ws_gtk *gtk)
{
    char filename[WS_GTK_COUNTER_FILENAME_LEN];

    ws_gtk_counter_filename(gtk->key, filename);
    storage_delete((const char *[]){ filename, NULL });
}
