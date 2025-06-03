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
#include <ns3/sl-wisun-linux.hpp>
#include <ns3/simulator.h>

extern "C" {
#include "common/memutils.h"

#include "ncp_ind.h"
}

ns3::Callback<void, const void *> g_ncp_ind_cb;

static void __ncp_send(sl_wisun_evt_t *ind_cpy)
{
    if (!g_ncp_ind_cb.IsNull())
        g_ncp_ind_cb(ind_cpy);
    free(ind_cpy);
}

void ncp_send(const sl_wisun_evt_t *ind)
{
    sl_wisun_evt_t *ind_cpy = (sl_wisun_evt_t *)xalloc(le16toh(ind->header.length));

    /*
     * NOTE: Indications are sent from a different thread than the main
     * simulation, so ScheduleWithContext() must be used. Consequently, the
     * indication packet memory must be kept valid until the callback is
     * invoked. A copy is made to ensure this.
     */
    memcpy(ind_cpy, ind, le16toh(ind->header.length));
    ns3::Simulator::ScheduleWithContext(g_simulation_id, ns3::Seconds(0),
                                        __ncp_send, ind_cpy);
}

void ncp_send_sk_data(int fd, const void *buf, size_t buf_len, const struct sockaddr_in6 *sin6)
{
    sl_wisun_evt_t *ind = (sl_wisun_evt_t *)xalloc(sizeof(sl_wisun_msg_socket_data_ind_t) + buf_len);

    ind->header.id     = SL_WISUN_MSG_SOCKET_DATA_IND_ID;
    ind->header.info   = 0;
    ind->header.length = htole16(sizeof(sl_wisun_msg_socket_data_ind_t) + buf_len);
    ind->evt.socket_data.socket_id      = fd;
    ind->evt.socket_data.status         = htole32(SL_STATUS_OK);
    ind->evt.socket_data.remote_address = sin6->sin6_addr;
    ind->evt.socket_data.remote_port    = sin6->sin6_port;
    ind->evt.socket_data.data_length    = htole16(buf_len);
    memcpy(ind->evt.socket_data.data, buf, buf_len);
    ns3::Simulator::ScheduleWithContext(g_simulation_id, ns3::Seconds(0),
                                        __ncp_send, ind);
}
