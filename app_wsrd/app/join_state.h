/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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

#ifndef JOIN_STATE_H
#define JOIN_STATE_H

struct wsrd;

enum wsrd_event {
    WSRD_EVENT_NONE = 0,
    WSRD_EVENT_PA_FROM_NEW_PAN,
    WSRD_EVENT_AUTH_SUCCESS,
    WSRD_EVENT_AUTH_FAIL,
    WSRD_EVENT_PC_RX,
    WSRD_EVENT_PC_TIMEOUT,
    WSRD_EVENT_PA_FROM_PREV_PAN,
    WSRD_EVENT_RPL_NEW_PREF_PARENT,
    WSRD_EVENT_ROUTING_SUCCESS,
    WSRD_EVENT_RPL_NO_CANDIDATE,
    WSRD_EVENT_PAN_TIMEOUT,
    WSRD_EVENT_COUNT,
};

enum wsrd_state {
    WSRD_STATE_DISCOVERY = 0,
    WSRD_STATE_RECONNECT,
    WSRD_STATE_AUTHENTICATE,
    WSRD_STATE_CONFIGURE,
    WSRD_STATE_RPL_PARENT,
    WSRD_STATE_ROUTING,
    WSRD_STATE_OPERATIONAL,
    WSRD_STATE_COUNT,
};

struct wsrd_state_transition {
    enum wsrd_event event;
    enum wsrd_state next_state;
};

struct wsrd_state_entry {
    enum wsrd_state state;
    const struct wsrd_state_transition *transitions;
    void (*enter)(struct wsrd *wsrd);
    void (*exit)(struct wsrd *wsrd);
};

struct wsrd;

void join_state_1_enter(struct wsrd *wsrd);
void join_state_3_reconnect_enter(struct wsrd *wsrd);
void join_state_3_enter(struct wsrd *wsrd);
void join_state_3_exit(struct wsrd *wsrd);
void join_state_4_choose_parent_enter(struct wsrd *wsrd);
void join_state_4_choose_parent_exit(struct wsrd *wsrd);
void join_state_4_routing_enter(struct wsrd *wsrd);
void join_state_5_enter(struct wsrd *wsrd);
void join_state_5_exit(struct wsrd *wsrd);

void join_state_transition(struct wsrd *wsrd, enum wsrd_event event);

#endif
