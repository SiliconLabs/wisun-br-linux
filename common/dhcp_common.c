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

#include <string.h>
#include <errno.h>

#include "common/specs/dhcpv6.h"
#include "common/iobuf.h"
#include "common/log.h"

#include "dhcp_common.h"

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

void dhcp_fill_client_id(struct iobuf_write *buf, uint16_t hwaddr_type, const uint8_t *hwaddr)
{
    BUG_ON(!hwaddr);
    BUG_ON(hwaddr_type != DHCPV6_DUID_HW_TYPE_EUI64 &&
           hwaddr_type != DHCPV6_DUID_HW_TYPE_IEEE802);

    iobuf_push_be16(buf, DHCPV6_OPT_CLIENT_ID);
    iobuf_push_be16(buf, 2 + 2 + 8);
    iobuf_push_be16(buf, DHCPV6_DUID_TYPE_LINK_LAYER);
    iobuf_push_be16(buf, hwaddr_type);
    iobuf_push_data(buf, hwaddr, 8);
}

void dhcp_fill_rapid_commit(struct iobuf_write *buf)
{
    iobuf_push_be16(buf, DHCPV6_OPT_RAPID_COMMIT);
    iobuf_push_be16(buf, 0);
}

void dhcp_fill_identity_association(struct iobuf_write *buf, uint32_t ia_id, const uint8_t ipv6[16],
                                    uint32_t preferred_lifetime, uint32_t valid_lifetime)
{
    uint16_t opt_len = 4 + 4 + 4;

    if (ipv6)
        opt_len += 2 + 2 + 16 + 4 + 4;
    iobuf_push_be16(buf, DHCPV6_OPT_IA_NA);
    iobuf_push_be16(buf, opt_len);
    iobuf_push_be32(buf, ia_id);
    iobuf_push_be32(buf, 0); // T1
    iobuf_push_be32(buf, 0); // T2
    if (ipv6) {
        iobuf_push_be16(buf, DHCPV6_OPT_IA_ADDRESS);
        iobuf_push_be16(buf, 16 + 4 + 4);
        iobuf_push_data(buf, ipv6, 16);
        iobuf_push_be32(buf, preferred_lifetime);
        iobuf_push_be32(buf, valid_lifetime);
    }
}
