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
#include "common/authenticator/authenticator_key.h"
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
#include "common/time_extra.h"

#include "authenticator_radius.h"

/*
 * RADIUS is specified in:
 * - RFC 2865 Remote Authentication Dial In User Service (RADIUS)
 * - RFC 3579 RADIUS (Remote Authentication Dial In User Service) Support For
 *   Extensible Authentication Protocol (EAP)
 * - RFC 2548 Microsoft Vendor-specific RADIUS Attributes
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
    RADIUS_ATTR_VENDOR   = 26,
    RADIUS_ATTR_EAP_MSG  = 79,
    RADIUS_ATTR_MSG_AUTH = 80,
};

// Private Enterprise Numbers
// https://www.iana.org/assignments/enterprise-numbers
#define PEN_MICROSOFT 311

// RFC 2548 2. Attributes
enum radius_attr_ms {
    RADIUS_ATTR_MS_MPPE_RECV_KEY = 17,
};

// RFC 2865 5. Attributes
struct radius_attr {
    uint8_t type;
    uint8_t len;
    uint8_t val[];
} __attribute__((packed));

void radius_init(struct auth_ctx *auth, const struct sockaddr *sa)
{
    union {
        struct sockaddr     sa;
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin;
    } u;
    int ret;

    switch (sa->sa_family) {
    case AF_INET:
        memcpy(&u, sa, sizeof(u.sin));
        u.sin.sin_port = htons(RADIUS_PORT);
        break;
    case AF_INET6:
        memcpy(&u, sa, sizeof(u.sin6));
        u.sin6.sin6_port = htons(RADIUS_PORT);
        break;
    default:
        BUG();
    }
    auth->radius_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    FATAL_ON(auth->radius_fd < 0, 2, "%s: socket: %m", __func__);
    ret = connect(auth->radius_fd, &u.sa, sizeof(u));
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

// NOTE: The same structure is used for vendor and regular attributes.
// RFC 2865 5.26. Vendor-Specific
static const struct radius_attr *radius_attr_find_vendor(const void *buf, size_t buf_len,
                                                         uint32_t vendor_id, uint8_t vendor_type)
{
    struct iobuf_read iobuf_attr = { };
    const struct radius_attr *attr;
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };

    while (iobuf_remaining_size(&iobuf)) {
        attr = radius_attr_find(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf), RADIUS_ATTR_VENDOR);
        if (!attr)
            return NULL;
        iobuf.cnt = (uintptr_t)attr - (uintptr_t)buf + attr->len;

        iobuf_attr.cnt       = 0;
        iobuf_attr.data      = attr->val;
        iobuf_attr.data_size = attr->len - sizeof(*attr);
        if (iobuf_pop_be32(&iobuf_attr) != vendor_id)
            continue;
        attr = radius_attr_find(iobuf_ptr(&iobuf_attr), iobuf_remaining_size(&iobuf_attr), vendor_type);
        if (attr)
            return attr;
    }
    return NULL;
}

/*
 *   RFC 2865 3. Packet Format
 * ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
 */
static int radius_verify_resp_auth(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                   const void *buf, size_t buf_len)
{
    const struct radius_hdr *hdr = buf;
    mbedtls_md5_context md5;
    uint8_t resp_auth[16];

    BUG_ON(buf_len < sizeof(struct radius_hdr));
    mbedtls_md5_init(&md5);
    xmbedtls_md5_starts(&md5);
    xmbedtls_md5_update(&md5, buf, offsetof(struct radius_hdr, auth));
    xmbedtls_md5_update(&md5, supp->radius_auth, 16);
    xmbedtls_md5_update(&md5, (uint8_t *)buf + sizeof(*hdr), buf_len - sizeof(*hdr));
    xmbedtls_md5_update(&md5, (uint8_t *)auth->cfg->radius_secret, strlen(auth->cfg->radius_secret));
    xmbedtls_md5_finish(&md5, resp_auth);
    mbedtls_md5_free(&md5);
    return !memcmp(hdr->auth, resp_auth, 16) ? 0 : -EINVAL;
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

/*
 *   RFC 2548 2.4.3. MS-MPPE-Recv-Key
 * Construct a plaintext version of the String field by concatenating the Key-
 * Length and Key sub-fields. If necessary, pad the resulting string until its
 * length (in octets) is an even multiple of 16. It is recommended that zero
 * octets (0x00) be used for padding. Call this plaintext P. Call the shared
 * secret S, the pseudo-random 128-bit Request Authenticator (from the
 * corresponding Access-Request packet) R, and the contents of the Salt field
 * A. Break P into 16 octet chunks p(1), p(2)...p(i), where i = len(P)/16. Call
 * the ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
 * Intermediate values b(1), b(2)...c(i) are required. Encryption is performed
 * in the following manner ('+' indicates concatenation):
 *   b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
 *   b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
 *     ...
 *   b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)
 * The resulting encrypted String field will contain c(1)+c(2)+...+c(i).
 * On receipt, the process is reversed to yield the plaintext String.
 */
static void radius_ms_mppe_key_decrypt(void *restrict out, const void *restrict in, size_t len,
                                       const char *secret, const uint8_t auth[16], const uint8_t salt[2])
{
    mbedtls_md5_context md5;
    const uint8_t *in8 = in;
    uint8_t *out8 = out;
    uint8_t b[16];

    BUG_ON(len % 16);
    mbedtls_md5_init(&md5);

    for (int i = len / 16 - 1; i > 0; i--) {
        xmbedtls_md5_starts(&md5);
        xmbedtls_md5_update(&md5, (uint8_t *)secret, strlen(secret));
        xmbedtls_md5_update(&md5, in8 + 16 * (i - 1), 16);
        xmbedtls_md5_finish(&md5, b);

        for (int j = 0; j < 16; j++)
            out8[16 * i + j] = in8[16 * i + j] ^ b[j];
    }

    xmbedtls_md5_starts(&md5);
    xmbedtls_md5_update(&md5, (uint8_t *)secret, strlen(secret));
    xmbedtls_md5_update(&md5, auth, 16);
    xmbedtls_md5_update(&md5, salt, 2);
    xmbedtls_md5_finish(&md5, b);

    for (int j = 0; j < 16; j++)
        out8[j] = in8[j] ^ b[j];

    mbedtls_md5_free(&md5);
}

// RFC 2548 2.4.3. MS-MPPE-Recv-Key
static int radius_read_ms_mppe_recv_key(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                        const void *buf, size_t buf_len)
{
    const struct radius_attr *attr;
    struct iobuf_read iobuf = { };
    uint8_t string[48];
    uint8_t salt[2];
    uint8_t key_len;

    iobuf.data      = buf;
    iobuf.data_size = buf_len;
    iobuf_pop_data_ptr(&iobuf, sizeof(struct radius_hdr));
    attr = radius_attr_find_vendor(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                                   PEN_MICROSOFT, RADIUS_ATTR_MS_MPPE_RECV_KEY);
    if (!attr)
        return -ENODATA;
    iobuf.cnt       = 0;
    iobuf.data      = attr->val;
    iobuf.data_size = attr->len - sizeof(*attr);
    iobuf_pop_data(&iobuf, salt, sizeof(salt));
    if (iobuf_remaining_size(&iobuf) != sizeof(string))
        return -EINVAL;

    radius_ms_mppe_key_decrypt(string, iobuf_ptr(&iobuf), sizeof(string),
                               auth->cfg->radius_secret, supp->radius_auth, salt);

    iobuf.cnt       = 0;
    iobuf.data      = string;
    iobuf.data_size = sizeof(string);
    key_len = iobuf_pop_u8(&iobuf);
    if (key_len != sizeof(supp->pmk))
        return -EINVAL;

    /*
     * Do not reinstall the key if it was already installed before to prevent Key
     * Reinstallation Attacks (KRACK)[1].
     *
     * [1]: https://www.krackattacks.com
     */
    if (!memcmp(supp->pmk, iobuf_ptr(&iobuf), sizeof(supp->pmk))) {
        WARN("sec: ignore reinstallation of pmk");
        return 0;
    }

    iobuf_pop_data(&iobuf, supp->pmk, sizeof(supp->pmk));
    supp->pmk_installation_s = time_now_s(CLOCK_MONOTONIC);
    /*
     *   IEEE 802.11-2020, 12.7.2 EAPOL-Key frames
     * d) Key Replay Counter. This field is represented as an unsigned integer,
     * and is initialized to 0 when the PMK is established.
     */
    supp->replay_counter = 0;
    return 0;
}

/*
 *   RFC 3579 3.2. Message-Authenticator
 * For Access-Challenge, Access-Accept, and Access-Reject packets, the Message-
 * Authenticator is calculated as follows, using the Request-Authenticator from
 * the Access-Request this packet is in reply to:
 *   Message-Authenticator = HMAC-MD5(Type, Identifier, Length,
 *                                    Request Authenticator, Attributes)
 * When the message integrity check is calculated the signature string should
 * be considered to be sixteen octets of zero. The shared secret is used as the
 * key for the HMAC-MD5 message integrity check.
 */
static int radius_verify_msg_auth(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                                  const void *buf, size_t buf_len)
{
    const struct radius_attr *attr;
    uint8_t msg_auth[16] = { };
    mbedtls_md_context_t md;
    int offset_msg_auth;

    BUG_ON(buf_len < sizeof(struct radius_hdr));
    attr = radius_attr_find((uint8_t *)buf + sizeof(struct radius_hdr),
                            buf_len - sizeof(struct radius_hdr),
                            RADIUS_ATTR_MSG_AUTH);
    if (!attr)
        return -ENODATA;
    if (attr->len != sizeof(*attr) + 16)
        return -EINVAL;

    offset_msg_auth = (uintptr_t)attr - (uintptr_t)buf + sizeof(*attr);
    mbedtls_md_init(&md);
    xmbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 1);
    xmbedtls_md_hmac_starts(&md, (uint8_t *)auth->cfg->radius_secret, strlen(auth->cfg->radius_secret));
    xmbedtls_md_hmac_update(&md, buf, offsetof(struct radius_hdr, auth));
    xmbedtls_md_hmac_update(&md, supp->radius_auth, 16);
    xmbedtls_md_hmac_update(&md, (uint8_t *)buf + sizeof(struct radius_hdr),
                                 offset_msg_auth - sizeof(struct radius_hdr));
    xmbedtls_md_hmac_update(&md, msg_auth, 16);
    xmbedtls_md_hmac_update(&md, (uint8_t *)buf + offset_msg_auth + 16,
                                 buf_len - offset_msg_auth - 16);
    xmbedtls_md_hmac_finish(&md, msg_auth);
    mbedtls_md_free(&md);
    return !memcmp(attr->val, msg_auth, 16) ? 0 : -EINVAL;
}

// Read an EAP packet from the RADIUS attributes and send it to the supplicant.
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
    timer_stop(&auth->timer_group, &supp->rt_timer);

    TRACE(TR_SECURITY, "sec: rx-radius code=%-16s id=%u",
          tr_radius_code(hdr->code), hdr->id);

    ret = radius_verify_resp_auth(auth, supp, iobuf.data, iobuf.data_size);
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: invalid response authenticator", "radius");
        return;
    }

    switch (hdr->code) {
    case RADIUS_ACCESS_CHALLENGE:
        ret = radius_read_state(supp, iobuf.data, iobuf.data_size);
        if (ret < 0) {
            TRACE(TR_DROP, "drop %-9s: missing state attribute", "radius");
            return;
        }
        break;
    case RADIUS_ACCESS_ACCEPT:
        // Use a vendor attribute to retrieve the PMK.
        ret = radius_read_ms_mppe_recv_key(auth, supp, iobuf.data, iobuf.data_size);
        if (ret < 0) {
            TRACE(TR_DROP, "drop %-9s: missing MS-MPPE-Recv-Key attribute", "radius");
            return;
        }
        break;
    case RADIUS_ACCESS_REJECT:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported code=%u", "radius", hdr->code);
        return;
    }

    ret = radius_verify_msg_auth(auth, supp, iobuf.data, iobuf.data_size);
    if (ret < 0) {
        if (hdr->code == RADIUS_ACCESS_REJECT)
            auth_eap_send_failure(auth, supp);
        else
            TRACE(TR_DROP, "drop %-9s: invalid message authenticator", "radius");
        return;
    }

    ret = radius_recv_eap(auth, supp, iobuf.data, iobuf.data_size);
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: malformed EAP frame", "radius");
        return;
    }

    if (hdr->code == RADIUS_ACCESS_ACCEPT)
        auth_key_pairwise_message_1_send(auth, supp);
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

void radius_send(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                 const void *buf, size_t buf_len)
{
    const struct radius_hdr *hdr = buf;
    ssize_t ret;

    BUG_ON(buf_len < sizeof(*hdr));
    TRACE(TR_SECURITY, "sec: tx-radius code=%-16s id=%u",
          tr_radius_code(hdr->code), hdr->id);
    ret = send(auth->radius_fd, buf, buf_len, 0);
    WARN_ON(ret < 0, "%s: send: %m", __func__);
}

void radius_send_eap(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                     const void *buf, size_t buf_len)
{
    const struct eap_hdr *eap = buf;
    struct radius_hdr hdr = { };
    struct pktbuf pktbuf = { };
    int offset_msg_auth;

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
                     (uint8_t *)auth->cfg->radius_secret, strlen(auth->cfg->radius_secret),
                     pktbuf_head(&pktbuf), pktbuf_len(&pktbuf),
                     pktbuf_head(&pktbuf) + offset_msg_auth);

    radius_send(auth, supp, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    auth_rt_timer_start(auth, supp, 0, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    pktbuf_free(&pktbuf);
}
