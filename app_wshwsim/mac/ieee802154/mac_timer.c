/*
 * Copyright (c) 2014-2017, Pelion and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include "mbed-client-libservice/ns_trace.h"
#include "nanostack-event-loop/eventOS_callback_timer.h"
#include "common/hal_interrupt.h"
#include "mac/ieee802154/sw_mac_internal.h"
#include "mac/ieee802154/mac_pd_sap.h"
#include "mac/ieee802154/mac_timer.h"
#include "nanostack/mac/sw_mac.h"
#define TRACE_GROUP "mTim"

/*-------------------MAC TIMER FUNCTIONS--------------------------*/


/**
 * \brief Function starts MAC timer.
 *
 * \param event MAC event to timeout
 * \param slots Number of MAC ticks (50us)
 *
 * \return none
 */
void timer_mac_start(protocol_interface_rf_mac_setup_s *rf_ptr, mac_event_t event, uint16_t slots)
{
    /*Save MAC event*/
    if (rf_ptr->mac_timer_id != -1) {
        rf_ptr->timer_mac_event = event;
        eventOS_callback_timer_start(rf_ptr->mac_timer_id, slots);
    }
}

/**
 * \brief Function stops MAC timer.
 *
 * \param none
 *
 * \return none
 */
void timer_mac_stop(protocol_interface_rf_mac_setup_s *rf_ptr)
{
    platform_enter_critical();
    if (rf_ptr->mac_timer_id != -1) {
        eventOS_callback_timer_stop(rf_ptr->mac_timer_id);
        rf_ptr->timer_mac_event = MAC_STATE_IDLE;
    }
    platform_exit_critical();
}

void timer_mac_interrupt(int timer_id, uint16_t slots)
{
    (void)slots;

    protocol_interface_rf_mac_setup_s *rf_mac_setup = get_sw_mac_ptr_by_timer(timer_id, ARM_NWK_MAC_TIMER);

    if (rf_mac_setup) {
        //SET State
        rf_mac_setup->mac_tx_result = rf_mac_setup->timer_mac_event;
        rf_mac_setup->timer_mac_event = MAC_STATE_IDLE;
        mac_pd_sap_state_machine(rf_mac_setup);
    }
}
