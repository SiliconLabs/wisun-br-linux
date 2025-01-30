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

/*
 *   Helpers to parse and write DHCP frames.
 * To create frames, dhcp_fill_*() appends DHCP options to the buffer.
 * To parse frames, the basic function is dhcp_get_option().
 * dhcp_get_*() allow to retrieve content of a specific DHCP option.
 * Finally, dhcp_check_*() check if the option is present and checks
 * option-specific values.
 */

#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "common/specs/dhcpv6.h"
#include "common/named_values.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/rand.h"
#include "common/log.h"

#include "dhcp_common.h"

static const char *tr_dhcp_type(uint8_t type)
{
    static const struct name_value table[] = {
        { "sol",      DHCPV6_MSG_SOLICIT },
        { "adv",      DHCPV6_MSG_ADVERT },
        { "req",      DHCPV6_MSG_REQUEST },
        { "confirm",  DHCPV6_MSG_CONFIRM },
        { "renew",    DHCPV6_MSG_RENEW },
        { "rebind",   DHCPV6_MSG_REBIND },
        { "rply",     DHCPV6_MSG_REPLY },
        { "release",  DHCPV6_MSG_RELEASE },
        { "decline",  DHCPV6_MSG_DECLINE },
        { "reconfig", DHCPV6_MSG_RECONFIGURE },
        { "info-req", DHCPV6_MSG_INFO_REQUEST },
        { "rel-fwd",  DHCPV6_MSG_RELAY_FWD },
        { "rel-rply", DHCPV6_MSG_RELAY_REPLY },
        { }
    };

    return val_to_str(type, table, "unknown");
}

void dhcp_trace_rx(const void *buf, size_t buf_len, const struct in6_addr *src)
{
    TRACE(TR_DHCP, "rx-dhcp %-9s src=%s",
          tr_dhcp_type(buf_len >= 1 ? *(const uint8_t *)buf : 0),
          tr_ipv6(src->s6_addr));
}

void dhcp_trace_tx(const void *buf, size_t buf_len, const struct in6_addr *dst)
{
    TRACE(TR_DHCP, "tx-dhcp %-9s dst=%s",
          tr_dhcp_type(buf_len >= 1 ? *(const uint8_t *)buf : 0),
          tr_ipv6(dst->s6_addr));
}

int dhcp_get_option(const uint8_t *data, size_t len, uint16_t option, struct iobuf_read *option_payload)
{
    uint16_t opt_type, opt_len;
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };

    memset(option_payload, 0, sizeof(struct iobuf_read));
    option_payload->err = true;
    while (iobuf_remaining_size(&input)) {
        opt_type = iobuf_pop_be16(&input);
        opt_len = iobuf_pop_be16(&input);
        if (opt_type == option) {
            option_payload->data = iobuf_pop_data_ptr(&input, opt_len);
            if (!option_payload->data)
                return -EINVAL;
            option_payload->err = false;
            option_payload->data_size = opt_len;
            return opt_len;
        }
        iobuf_pop_data_ptr(&input, opt_len);
    }
    return -ENOENT;
}

static int dhcp_opt_push(struct iobuf_write *buf, uint16_t opt)
{
    int offset;

    iobuf_push_be16(buf, opt);
    offset = buf->len;
    // Length is filled by calling dhcp_opt_fill() with the returned offset.
    iobuf_push_be16(buf, 0);
    return offset;
}

static void dhcp_opt_fill(struct iobuf_write *buf, int offset)
{
    const size_t len = buf->len - offset - 2;

    BUG_ON(buf->data[offset]);
    BUG_ON(len > UINT16_MAX);
    write_be16(buf->data + offset, len);
}

void dhcp_fill_client_id(struct iobuf_write *buf, uint16_t hwaddr_type, const uint8_t *hwaddr)
{
    int len_offset;

    BUG_ON(!hwaddr);
    BUG_ON(hwaddr_type != DHCPV6_DUID_HW_TYPE_EUI64 &&
           hwaddr_type != DHCPV6_DUID_HW_TYPE_IEEE802);

    len_offset = dhcp_opt_push(buf, DHCPV6_OPT_CLIENT_ID);
    iobuf_push_be16(buf, DHCPV6_DUID_TYPE_LINK_LAYER);
    iobuf_push_be16(buf, hwaddr_type);
    iobuf_push_data(buf, hwaddr, 8);
    dhcp_opt_fill(buf, len_offset);
}

void dhcp_fill_rapid_commit(struct iobuf_write *buf)
{
    int len_offset = dhcp_opt_push(buf, DHCPV6_OPT_RAPID_COMMIT);

    dhcp_opt_fill(buf, len_offset);
}

void dhcp_fill_identity_association(struct iobuf_write *buf, uint32_t ia_id, const uint8_t ipv6[16],
                                    uint32_t preferred_lifetime, uint32_t valid_lifetime)
{
    int len_offset = dhcp_opt_push(buf, DHCPV6_OPT_IA_NA);
    int addr_len_offset;

    iobuf_push_be32(buf, ia_id);
    iobuf_push_be32(buf, 0); // T1
    iobuf_push_be32(buf, 0); // T2
    if (ipv6) {
        addr_len_offset = dhcp_opt_push(buf, DHCPV6_OPT_IA_ADDRESS);
        iobuf_push_data(buf, ipv6, 16);
        iobuf_push_be32(buf, preferred_lifetime);
        iobuf_push_be32(buf, valid_lifetime);
        dhcp_opt_fill(buf, addr_len_offset);
    }
    dhcp_opt_fill(buf, len_offset);
}

void dhcp_fill_server_id(struct iobuf_write *buf, const uint8_t eui64[8])
{
    int len_offset = dhcp_opt_push(buf, DHCPV6_OPT_SERVER_ID);

    iobuf_push_be16(buf, DHCPV6_DUID_TYPE_LINK_LAYER);
    iobuf_push_be16(buf, DHCPV6_DUID_HW_TYPE_EUI64);
    iobuf_push_data(buf, eui64, 8);
    dhcp_opt_fill(buf, len_offset);
}

void dhcp_fill_elapsed_time(struct iobuf_write *buf, struct timespec *start)
{
    uint32_t elapsed_time;
    struct timespec tp;
    int len_offset;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    if (!start->tv_sec)
        *start = tp;
    elapsed_time = (tp.tv_sec - start->tv_sec) * 100;
    elapsed_time += (tp.tv_nsec - start->tv_nsec) / 10000;
    len_offset = dhcp_opt_push(buf, DHCPV6_OPT_ELAPSED_TIME);
    if (elapsed_time > 0xFFFF)
        iobuf_push_be16(buf, 0xFFFF);
    else
        iobuf_push_be16(buf, elapsed_time);
    dhcp_opt_fill(buf, len_offset);
}

int dhcp_get_client_hwaddr(const uint8_t *req, size_t req_len, const uint8_t **hwaddr)
{
    uint16_t duid_type, ll_type;
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_CLIENT_ID, &opt);
    if (opt.err)
        return -EINVAL;
    duid_type = iobuf_pop_be16(&opt);
    ll_type = iobuf_pop_be16(&opt);
    if (duid_type != DHCPV6_DUID_TYPE_LINK_LAYER ||
        (ll_type != DHCPV6_DUID_HW_TYPE_EUI64 && ll_type != DHCPV6_DUID_HW_TYPE_IEEE802)) {
        TRACE(TR_DROP, "drop %-9s: unsupported client ID option", "dhcp");
        return -ENOTSUP;
    }
    *hwaddr = iobuf_pop_data_ptr(&opt, 8);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: malformed client ID option", "dhcp");
        return -EINVAL;
    }
    return ll_type;
}

uint32_t dhcp_get_identity_association_id(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;
    uint32_t ia_id;

    dhcp_get_option(req, req_len, DHCPV6_OPT_IA_NA, &opt);
    ia_id = iobuf_pop_be32(&opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing IA_NA option", "dhcp");
        return UINT32_MAX;
    }
    return ia_id;
}

/*
 *   RFC3315 - Section 14
 * Each of the computations of a new RT include a randomization factor
 * (RAND), which is a random number chosen with a uniform distribution
 * between -0.1 and +0.1.
 */
int dhcp_get_random(int rt)
{
    return randf_range(-0.1, 0.1) * rt;
}

int dhcp_check_status_code(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;
    uint16_t status;

    dhcp_get_option(req, req_len, DHCPV6_OPT_STATUS_CODE, &opt);
    if (opt.err)
        return 0;
    status = iobuf_pop_be16(&opt);
    if (status) {
        TRACE(TR_DROP, "drop %-9s: status code %d", "dhcp", status);
        return -EFAULT;
    }
    return 0;
}

int dhcp_check_rapid_commit(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_RAPID_COMMIT, &opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing rapid commit option", "dhcp");
        return -ENOTSUP;
    }
    return 0;
}

int dhcp_check_elapsed_time(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_ELAPSED_TIME, &opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing elapsed time option", "dhcp");
        return -EINVAL; // Elapsed Time option is mandatory
    }
    return 0;
}

int dhcp_check_server_id(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_SERVER_ID, &opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing server ID option", "dhcp");
        return -ENOTSUP;
    }
    return 0;
}

int dhcp_check_client_id(const uint8_t expected_eui64[8], const uint8_t *req, size_t req_len)
{
    const uint8_t *hwaddr;
    int ret = dhcp_get_client_hwaddr(req, req_len, &hwaddr);

    if (ret < 0)
        return ret;

    if (memcmp(hwaddr, expected_eui64, 8)) {
        TRACE(TR_DROP, "drop %-9s: invalid client ID option", "dhcp");
        return -EINVAL;
    }
    return 0;
}
