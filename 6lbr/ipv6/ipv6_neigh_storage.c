/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <linux/limits.h>
#include <arpa/inet.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <glob.h>

#include "common/key_value_storage.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/parsers.h"
#include "common/endian.h"
#include "common/log.h"

#include "ipv6/ipv6_neigh_storage.h"
#include "ipv6/ipv6_routing_table.h"
#include "net/protocol.h"
#include "app/tun.h"

static void ipv6_neigh_storage_delete(const uint8_t *eui64)
{
    char filename[PATH_MAX];

    sprintf(filename, "neighbor-");
    str_eui64(eui64, filename + strlen(filename));
    storage_delete((const char *[]){ filename, NULL });
}

void ipv6_neigh_storage_save(struct ipv6_neighbour_cache *cache, const uint8_t *eui64)
{
    char ipv6_str[INET6_ADDRSTRLEN];
    char time_str[STR_MAX_LEN_DATE];
    struct storage_parse_info *nvm;
    char filename[PATH_MAX];
    time_t ts;
    int i = 0;

    sprintf(filename, "neighbor-");
    str_eui64(eui64, filename + strlen(filename));
    nvm = storage_open_prefix(filename, "w");

    if (!nvm) {
        WARN("%s %s failure", __func__, filename);
        return;
    }

    ns_list_foreach(struct ipv6_neighbour, cur, &cache->list) {
        if (memcmp(eui64, ipv6_neighbour_eui64(cache, cur), 8))
            continue;
        if (!cur->lifetime_s || !cur->expiration_s)
            continue;
        ts = cur->expiration_s + time_get_storage_offset();
        str_date(ts, time_str);
        str_ipv6(cur->ip_address, ipv6_str);
        fprintf(nvm->file, "ipv6[%d] = %s\n", i, ipv6_str);
        fprintf(nvm->file, "lifetime[%d] = %u\n", i, cur->lifetime_s);
        fprintf(nvm->file, "# %s\n", time_str);
        fprintf(nvm->file, "expiration[%d] = %lu\n", i, ts);
        i++;
    }

    storage_close(nvm);

    if (!i)
        ipv6_neigh_storage_delete(eui64);
}

static void ipv6_neigh_storage_load_neigh(struct ipv6_neighbour_cache *cache, const char *filename)
{
    struct net_if *cur = container_of(cache, struct net_if, ipv6_neighbour_cache);
    struct ipv6_neighbour *ipv6_neighbors;
    struct ipv6_neighbour *ipv6_neigh;
    struct storage_parse_info *nvm;
    const char *strptr;
    sockaddr_t ll_addr;
    int array_len = 2;
    uint8_t eui64[8];
    int ret;

    strptr = strrchr(filename, '-');
    if (!strptr) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    if (parse_byte_array(eui64, sizeof(eui64), strptr + 1)) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    nvm = storage_open(filename, "r");
    if (!nvm) {
        WARN("%s %s failure", __func__, filename);
        return;
    }

    ipv6_neighbors = calloc(array_len, sizeof(struct ipv6_neighbour));
    FATAL_ON(!ipv6_neighbors, 2, "%s %s", __func__, filename);

    while (true) {
        ret = storage_parse_line(nvm);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", nvm->filename, nvm->linenr, nvm->line);
            continue;
        }

        FATAL_ON(nvm->key_array_index > array_len, 1, "%s: invalid key index: %d", __func__, nvm->key_array_index);

        if (nvm->key_array_index == array_len) {
            ipv6_neighbors = reallocarray(ipv6_neighbors, array_len + 1, sizeof(struct ipv6_neighbour));
            FATAL_ON(!ipv6_neighbors, 2, "%s", __func__);
            memset(&ipv6_neighbors[array_len], 0, sizeof(struct ipv6_neighbour));
            array_len++;
        }

        if (!fnmatch("ipv6\\[*]", nvm->key, 0)) {
            ret = inet_pton(AF_INET6, nvm->value, ipv6_neighbors[nvm->key_array_index].ip_address);
            WARN_ON(ret != 1, "%s:%d: invalid value: %s", nvm->filename, nvm->linenr, nvm->value);
            ipv6_neighbors[nvm->key_array_index].type = IP_NEIGHBOUR_REGISTERED;
        } else if (!fnmatch("lifetime\\[*]", nvm->key, 0)) {
            ipv6_neighbors[nvm->key_array_index].lifetime_s = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("expiration\\[*]", nvm->key, 0)) {
            ipv6_neighbors[nvm->key_array_index].expiration_s = strtoull(nvm->value, NULL, 0) - time_get_storage_offset();
        } else {
            WARN("%s:%d: invalid key: '%s'", nvm->filename, nvm->linenr, nvm->line);
        }
    }

    for (int i = 0; i < array_len; i++) {
        if (!ipv6_neighbors[i].lifetime_s || !ipv6_neighbors[i].expiration_s ||
            ipv6_neighbors[i].type != IP_NEIGHBOUR_REGISTERED)
            continue;
        if (IN6_IS_ADDR_MULTICAST(ipv6_neighbors[i].ip_address) &&
            ipv6_neighbour_lookup_mc(cache, ipv6_neighbors[i].ip_address,
                                     ipv6_neighbour_eui64(cache, &ipv6_neighbors[i])))
            continue;
        else if (ipv6_neighbour_lookup(cache, ipv6_neighbors[i].ip_address))
            continue;

        memset(&ll_addr, 0, sizeof(ll_addr));
        ipv6_neigh = ipv6_neighbour_create(cache, ipv6_neighbors[i].ip_address, eui64);
        FATAL_ON(!ipv6_neigh, 2, "ipv6_neighbour_create()");

        ipv6_neigh->lifetime_s = ipv6_neighbors[i].lifetime_s;
        ipv6_neigh->expiration_s = ipv6_neighbors[i].expiration_s;
        // ll_address is a combination of PAN_ID and EUI-64
        ll_addr.addr_type = ADDR_802_15_4_LONG;
        write_be16(ll_addr.address, cur->ws_info.pan_information.pan_id);
        memcpy(ll_addr.address + PAN_ID_LEN, eui64, 8);
        // the neighbor state is set to stale
        ipv6_neighbour_entry_update_unsolicited(cache, ipv6_neigh, ll_addr.addr_type, ll_addr.address);
        ipv6_neigh->type = IP_NEIGHBOUR_REGISTERED;
    }

    storage_close(nvm);
    free(ipv6_neighbors);
}

void ipv6_neigh_storage_load(struct ipv6_neighbour_cache *cache)
{
    char pattern[PATH_MAX];
    glob_t globbuf;
    int ret;

    sprintf(pattern, "%s%s", g_storage_prefix, "neighbor-*");
    ret = glob(pattern, 0, NULL, &globbuf);
    if (ret && ret != GLOB_NOMATCH)
        WARN("%s: glob %s returned %u", __func__, pattern, ret);
    if (ret)
        return;

    for (int i = 0; globbuf.gl_pathv[i]; i++)
        ipv6_neigh_storage_load_neigh(cache, globbuf.gl_pathv[i]);
}
