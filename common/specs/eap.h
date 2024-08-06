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
#ifndef COMMON_SPECS_EAP_H
#define COMMON_SPECS_EAP_H

// RFC3748, 4 - EAP Packet Format
enum {
    EAP_CODE_REQUEST  = 1,
    EAP_CODE_RESPONSE = 2,
    EAP_CODE_SUCCESS  = 3,
    EAP_CODE_FAILURE  = 4,
};

// IANA - Method Types
// https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4
enum {
    // RFC3748, 5 - Initial EAP Request/Response Types
    EAP_TYPE_IDENTITY     = 1,
    EAP_TYPE_NOTIFICATION = 2,
    EAP_TYPE_NAK          = 3,

    // ...

    // RFC5216, 3.1 - EAP-TLS Request Packet
    EAP_TYPE_TLS          = 13,
};

// RFC5216, 3.1 - EAP-TLS Request Packet
#define EAP_TLS_FLAGS_LENGTH_MASK         0b10000000
#define EAP_TLS_FLAGS_MORE_FRAGMENTS_MASK 0b01000000
#define EAP_TLS_FLAGS_START_MASK          0b00100000

#endif
