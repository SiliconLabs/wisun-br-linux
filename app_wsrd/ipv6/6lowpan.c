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
#include <errno.h>

#include "common/specs/6lowpan.h"
#include "common/ipv6/6lowpan_iphc.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/pktbuf.h"
#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/app/ws.h"
#include "6lowpan.h"

void lowpan_recv(struct ipv6_ctx *ipv6,
                 const uint8_t *buf, size_t buf_len,
                 const uint8_t src[8], const uint8_t dst[8])
{
    uint8_t src_iid[8], dst_iid[8];
    struct pktbuf pktbuf = { };
    uint8_t dispatch;

    ipv6_addr_conv_iid_eui64(src_iid, src);
    ipv6_addr_conv_iid_eui64(dst_iid, dst);

    pktbuf_init(&pktbuf, buf, buf_len);

    if (pktbuf_len(&pktbuf) < 1)
        return;
    dispatch = pktbuf.buf[pktbuf.offset_head];

    // TODO: support FRAG1 and FRAGN
    if (LOWPAN_DISPATCH_IS_IPHC(dispatch)) {
        lowpan_iphc_decmpr(&pktbuf, src_iid, dst_iid);
    } else {
        TRACE(TR_DROP, "drop %-9s: unsupported dispatch type 0x%02x", "6lowpan", dispatch);
        goto err;
    }

    ipv6_recvfrom_mac(ipv6, &pktbuf);
err:
    pktbuf_free(&pktbuf);
}

int lowpan_send(struct ipv6_ctx *ipv6,
                 struct pktbuf *pktbuf,
                 const uint8_t src[8],
                 const uint8_t dst[8])
{
    uint8_t src_iid[8], dst_iid[8];

    ipv6_addr_conv_iid_eui64(src_iid, src);
    ipv6_addr_conv_iid_eui64(dst_iid, dst);

    lowpan_iphc_cmpr(pktbuf, src_iid, dst_iid);
    if (pktbuf->err)
        return -EINVAL;

    return ipv6->sendto_mac(ipv6, pktbuf, dst);
}
