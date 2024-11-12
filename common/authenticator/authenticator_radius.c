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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>

#include "common/authenticator/authenticator.h"
#include "common/authenticator/authenticator_eap.h"
#include "common/specs/eap.h"
#include "common/specs/eapol.h"
#include "common/specs/ieee802159.h"
#include "common/eap.h"
#include "common/eapol.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mbedtls_extra.h"
#include "common/memutils.h"
#include "common/named_values.h"
#include "common/pktbuf.h"
#include "common/rand.h"
#include "common/sys_queue_extra.h"

#include "authenticator_radius.h"

/*
 * RADIUS is specified in:
 * - RFC 2865 Remote Authentication Dial In User Service (RADIUS)
 * - RFC 3579 RADIUS (Remote Authentication Dial In User Service) Support For
 *   Extensible Authentication Protocol (EAP)
 * - IANA: https://www.iana.org/assignments/radius-types/radius-types.xhtml
 */

#define RADIUS_PORT 1812

// RFC 2865 4. Packet Types
enum radius_type {
    RADIUS_ACCESS_REQUEST   =  1,
    RADIUS_ACCESS_ACCEPT    =  2,
    RADIUS_ACCESS_REJECT    =  3,
    RADIUS_ACCESS_CHALLENGE = 11,
};

static const char *tr_radius_code(uint8_t code)
{
    static const struct name_value table[] = {
        { "access-request",   RADIUS_ACCESS_REQUEST },
        { "access-accept",    RADIUS_ACCESS_ACCEPT },
        { "access-reject",    RADIUS_ACCESS_REJECT },
        { "access-challenge", RADIUS_ACCESS_CHALLENGE },
        { }
    };

    return val_to_str(code, table, "unknown");
}

// RFC 2865 3. Packet Format
struct radius_hdr {
    uint8_t code;
    uint8_t id;
    be16_t  len;
    uint8_t auth[16];
} __attribute__((packed));

// RADIUS Attribute Types
// https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-2
enum radius_attr_type {
    RADIUS_ATTR_STATE    = 24,
    RADIUS_ATTR_EAP_MSG  = 79,
    RADIUS_ATTR_MSG_AUTH = 80,
};

// RFC 2865 5. Attributes
struct radius_attr {
    uint8_t type;
    uint8_t len;
    uint8_t val[];
} __attribute__((packed));

void radius_init(struct auth_ctx *auth, const struct in6_addr *srv_addr)
{
    struct sockaddr_in6 sa = {
        .sin6_family = AF_INET6,
        .sin6_addr = *srv_addr,
        .sin6_port = htons(RADIUS_PORT),
    };
    int ret;

    auth->radius_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(auth->radius_fd < 0, 2, "%s: socket: %m", __func__);
    ret = connect(auth->radius_fd, (struct sockaddr *)&sa, sizeof(sa));
    FATAL_ON(ret < 0, 2, "%s: connect: %m", __func__);
}

// RFC 2865 5. Attributes
static const struct radius_attr *radius_attr_find(const void *buf, size_t buf_len, uint8_t type)
{
    const struct radius_attr *attr;
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };

    while (iobuf_remaining_size(&iobuf) > sizeof(*attr)) {
        attr = (const struct radius_attr *)iobuf_ptr(&iobuf);
        if (attr->len < sizeof(*attr))
            return NULL;
        if (!iobuf_pop_data_ptr(&iobuf, attr->len))
            return NULL;
        if (attr->type == type)
            return attr;
    }
    return NULL;
}

// RFC 2865 5.24. State
static int radius_read_state(struct auth_supp_ctx *supp, const void *buf, size_t buf_len)
{
    const struct radius_attr *attr;

    BUG_ON(buf_len < sizeof(struct radius_hdr));
    attr = radius_attr_find((uint8_t *)buf + sizeof(struct radius_hdr),
                            buf_len - sizeof(struct radius_hdr),
                            RADIUS_ATTR_STATE);
    if (!attr)
        return -EINVAL;
    supp->radius_state_len = attr->len - sizeof(*attr);
    memcpy(supp->radius_state, attr->val, supp->radius_state_len);
    return 0;
}

// RFC 3579 3.1. EAP-Message
static int radius_recv_eap(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                              const void *buf, size_t buf_len)
{
    const struct radius_attr *attr;
    const struct eap_hdr *eap;
    struct pktbuf pktbuf = { };
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };

    iobuf_pop_data_ptr(&iobuf, sizeof(struct radius_hdr));
    attr = radius_attr_find(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf), RADIUS_ATTR_EAP_MSG);
    if (!attr || attr->len < sizeof(*attr) + sizeof(*eap))
        goto malformed;
    eap = (const struct eap_hdr *)attr->val;
    pktbuf_push_tail(&pktbuf, attr->val, attr->len - sizeof(*attr));
    iobuf.cnt = (uintptr_t)attr - (uintptr_t)iobuf.data + attr->len;

    while (pktbuf_len(&pktbuf) < ntohs(eap->length) && !iobuf.err) {
        attr = radius_attr_find(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf), RADIUS_ATTR_EAP_MSG);
        if (!attr)
            goto malformed;
        pktbuf_push_tail(&pktbuf, attr->val, attr->len - sizeof(*attr));
        iobuf.cnt = (uintptr_t)attr - (uintptr_t)iobuf.data + attr->len;
    }

    if (pktbuf_len(&pktbuf) < ntohs(eap->length))
        goto malformed;

    auth_eap_send(auth, supp, &pktbuf);
    pktbuf_free(&pktbuf);
    return 0;

malformed:
    pktbuf_free(&pktbuf);
    return -EINVAL;
}

void radius_recv(struct auth_ctx *auth)
{
    struct iobuf_read iobuf = { };
    const struct radius_hdr *hdr;
    struct auth_supp_ctx *supp;
    uint8_t buf[1024];
    int ret;

    iobuf.data = buf;
    iobuf.data_size = recv(auth->radius_fd, buf, sizeof(buf), 0);
    if (iobuf.data_size < 0) {
        WARN("%s: recv: %m", __func__);
        return;
    }

    hdr = iobuf_pop_data_ptr(&iobuf, sizeof(*hdr));
    if (!hdr || ntohs(hdr->len) > iobuf.data_size) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "radius");
        return;
    }
    iobuf.data_size = ntohs(hdr->len);

    supp = SLIST_FIND(supp, &auth->supplicants, link, supp->radius_id == hdr->id);
    if (!supp) {
        TRACE(TR_DROP, "drop %-9s: unknown id=%u", "radius", hdr->id);
        return;
    }
    supp->radius_id = -1; // Transaction finished

    TRACE(TR_SECURITY, "sec: rx-radius code=%-16s id=%u",
          tr_radius_code(hdr->code), hdr->id);

    switch (hdr->code) {
    case RADIUS_ACCESS_CHALLENGE:
        ret = radius_read_state(supp, iobuf.data, iobuf.data_size);
        if (ret < 0) {
            TRACE(TR_DROP, "drop %-9s: missing state attribute", "radius");
            return;
        }
        break;
    case RADIUS_ACCESS_ACCEPT:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported code=%u", "radius", hdr->code);
        return;
    }

    ret = radius_recv_eap(auth, supp, iobuf.data, iobuf.data_size);
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: malformed EAP frame", "radius");
        return;
    }
}

static void radius_attr_push(struct pktbuf *pktbuf, uint8_t type, const void *val, uint8_t val_len)
{
    struct radius_attr attr = {
        .type = type,
        .len  = sizeof(attr) + val_len,
    };

    BUG_ON(attr.len < val_len);
    pktbuf_push_tail(pktbuf, &attr, sizeof(attr));
    pktbuf_push_tail(pktbuf, val, val_len);
}

static int radius_id_new(struct auth_ctx *auth)
{
    struct auth_supp_ctx *supp;
    int cnt, id;

    // If next handle is already in use (unlikely), use the next available one.
    for (cnt = 0; cnt <= UINT8_MAX; cnt++) {
        id = auth->radius_id_next++;
        if (!SLIST_FIND(supp, &auth->supplicants, link, supp->radius_id == id))
            break;
    }
    return cnt <= UINT8_MAX ? id : -1;
}

void radius_send_eap(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                     const void *buf, size_t buf_len)
{
    const struct eap_hdr *eap = buf;
    struct radius_hdr hdr = { };
    struct pktbuf pktbuf = { };
    int offset_msg_auth;
    ssize_t ret;

    supp->radius_id = -1; // Cancel any on-going transaction
    supp->radius_id = radius_id_new(auth);
    if (supp->radius_id < 0) {
        TRACE(TR_DROP, "drop %-9s: too many on-going transations", "radius");
        return;
    }

    BUG_ON(buf_len < sizeof(*eap));
    hdr.code = RADIUS_ACCESS_REQUEST;
    hdr.id   = supp->radius_id;
    rand_get_n_bytes_random(supp->radius_auth, 16);
    memcpy(hdr.auth, supp->radius_auth, 16);
    pktbuf_push_tail(&pktbuf, &hdr, sizeof(hdr));

    // RFC 3579 3.1. EAP-Message
    while (buf_len > UINT8_MAX - sizeof(struct radius_attr)) {
        radius_attr_push(&pktbuf, RADIUS_ATTR_EAP_MSG,
                         buf, UINT8_MAX - sizeof(struct radius_attr));
        buf     += UINT8_MAX - sizeof(struct radius_attr);
        buf_len -= UINT8_MAX - sizeof(struct radius_attr);
    }
    if (buf_len)
        radius_attr_push(&pktbuf, RADIUS_ATTR_EAP_MSG, buf, buf_len);

    offset_msg_auth = pktbuf.offset_tail + sizeof(struct radius_attr);
    radius_attr_push(&pktbuf, RADIUS_ATTR_MSG_AUTH, NULL, 16);

    if (supp->radius_state_len)
        radius_attr_push(&pktbuf, RADIUS_ATTR_STATE,
                         supp->radius_state, supp->radius_state_len);

    // Fill length
    hdr.len = htons(pktbuf_len(&pktbuf));
    memcpy(pktbuf_head(&pktbuf) + offsetof(struct radius_hdr, len),
           &hdr.len, sizeof(hdr.len));

    xmbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5),
                     (uint8_t *)auth->radius_secret, strlen(auth->radius_secret),
                     pktbuf_head(&pktbuf), pktbuf_len(&pktbuf),
                     pktbuf_head(&pktbuf) + offset_msg_auth);

    TRACE(TR_SECURITY, "sec: tx-radius code=%-16s id=%u",
          tr_radius_code(hdr.code), hdr.id);
    ret = send(auth->radius_fd, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf), 0);
    WARN_ON(ret < 0, "%s: send: %m", __func__);
    pktbuf_free(&pktbuf);
}
