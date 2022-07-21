/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_COMMANDLINE_H
#define WSBR_COMMANDLINE_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h> // Compatibility with linux headers < 4.12
#include <linux/limits.h>
#include <linux/if.h>
#include <netinet/in.h>

#include "stack/net_interface.h"

// This struct is filled by parse_commandline() and never modified after.
struct wsbrd_conf {
    bool list_rf_configs;

    char cpc_instance[PATH_MAX];

    char uart_dev[PATH_MAX];
    int  uart_baudrate;
    bool uart_rtscts;

    char tun_dev[IFNAMSIZ];
    bool tun_autoconf;
    bool tun_use_tap;

    char ws_name[33]; // null-terminated string of 32 chars
    int  ws_size;
    int  ws_domain;
    int  ws_mode;
    int  ws_class;
    int  ws_regional_regulation;
    int  ws_chan0_freq;
    int  ws_chan_spacing;
    int  ws_chan_count;
    uint32_t ws_allowed_channels[8];
    int  ws_phy_mode_id;
    int  ws_chan_plan_id;

    uint8_t ipv6_prefix[16];
    struct sockaddr_in6 dhcpv6_server;

    char storage_prefix[PATH_MAX];
    arm_certificate_entry_s tls_own;
    arm_certificate_entry_s tls_ca;
    uint8_t ws_gtk[4][16];
    bool ws_gtk_force[4];
    struct sockaddr_storage radius_server;
    char radius_secret[256];

    int  tx_power;
    int  ws_fan_version;
    int  ws_pan_id;
    int  ws_pmk_lifetime;
    int  ws_ptk_lifetime;
    int  ws_gtk_expire_offset;
    int  ws_gtk_new_activation_time;
    int  ws_gtk_new_install_required;
    int  ws_revocation_lifetime_reduction;
    int  ws_gtk_max_mismatch;
    int  uc_dwell_interval;
    int  bc_dwell_interval;
    int  bc_interval;

    uint8_t ws_allowed_mac_addresses[10][8];
    uint8_t ws_allowed_mac_address_count;
    uint8_t ws_denied_mac_addresses[10][8];
    uint8_t ws_denied_mac_address_count;
};

void print_help_br(FILE *stream);
void print_help_node(FILE *stream);

void parse_commandline(struct wsbrd_conf *config, int argc, char *argv[],
                       void (*print_help)(FILE *stream));

#endif

