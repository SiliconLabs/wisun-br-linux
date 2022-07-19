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
#define _GNU_SOURCE
#include "nsconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "common/named_values.h"
#include "common/os_types.h"
#include "common/ws_regdb.h"
#include "common/parsers.h"
#include "common/utils.h"
#include "common/log.h"
#include "service_libs/utils/ns_file_system.h"
#include "stack/ws_management_api.h"

#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/core/ns_address_internal.h"

#include "commandline_values.h"
#include "wsbr.h"

#include "commandline.h"

static const int valid_ws_modes[] = {
    0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05,
    0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xb3, 0xb4, 0xb5, 0xb6,
    0xc4, 0xc5, 0xc6,
    0xd4, 0xd5, 0xd6,
};

static const int valid_ws_classes[] = {
    0x01, 0x02, 0x03, 0x04,                         // Legacy
    0x81, 0x82, 0x83, 0x84, 0x85,                   // ChanPlanIDs NA/BZ
    0x95, 0x96, 0x97, 0x98,                         // ChanPlanIDs JP
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // ChanPlanIDs EU
};

static const int valid_ws_chan_spacing[] = {
    100000, 200000, 400000, 600000, 800000, 1200000,
};

void print_help_br(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsbrd [OPTIONS]\n");
    fprintf(stream, "  wsbrd [OPTIONS] --list-rf-configs\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif, hif-extra,\n");
    fprintf(stream, "                           trickle, 15.4-mngt, 15.4, eap, icmp-rf, icmp-tun, dhcp\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -l, --list-rf-configs Retrieve the possible RF configurations from teh RCP then exit. Most\n");
    fprintf(stream, "                          of parameters are ignored in this mode\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU, NA, JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b (default), 2a, 2b, 3, 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1 (default), 2, 3 or 4\n");
    fprintf(stream, "  -S, --size=SIZE       Optimize network timings considering the number of expected nodes on\n");
    fprintf(stream, "                          the network. Valid values: CERT (development and certification),\n");
    fprintf(stream, "                          S (< 100, default), M (100-800), L (800-2500), XL (> 2500)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM od DER\n");
    fprintf(stream, "  format.\n");
    fprintf(stream, "  -K, --key=FILE         Private key (keep it secret)\n");
    fprintf(stream, "  -C, --certificate=FILE Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE   Certificate of the authority (CA) (shared with all devices of the\n");
    fprintf(stream, "                           network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
}

void print_help_node(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Simulate a Wi-SUN node\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsnode [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif, hif-extra\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU, NA, JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b (default), 2a, 2b, 3, 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1 (default), 2, 3 or 4\n");
    fprintf(stream, "  -S, --size=SIZE       Optimize network timings considering the number of expected nodes on\n");
    fprintf(stream, "                          the network. Valid values: CERT (development and certification),\n");
    fprintf(stream, "                          S (< 100, default), M (100-800), L (800-2500), XL (> 2500)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM\n");
    fprintf(stream, "  or DER format.\n");
    fprintf(stream, "  -K, --key=FILE         Private key (keep it secret)\n");
    fprintf(stream, "  -C, --certificate=FILE Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE   Certificate of the authority (CA) (shared with all devices of the\n");
    fprintf(stream, "                           network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsnode -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
}

static int read_cert(const char *filename, const uint8_t **ptr)
{
    uint8_t *tmp;
    int fd, ret;
    struct stat st;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;
    ret = fstat(fd, &st);
    if (ret < 0)
        return -1;

    /* See https://github.com/ARMmbed/mbedtls/issues/3896 and
     * mbedtls_x509_crt_parse()
     */
    tmp = malloc(st.st_size + 1);
    tmp[st.st_size] = 0;
    ret = read(fd, tmp, st.st_size);
    if (ret != st.st_size)
        return -1;
    close(fd);
    if (*ptr)
        free((uint8_t *)*ptr);
    *ptr = tmp;

    if (strstr((char *)tmp, "-----BEGIN CERTIFICATE-----"))
        return st.st_size + 1;
    else if (strstr((char *)tmp, "-----BEGIN PRIVATE KEY-----"))
        return st.st_size + 1;
    else
        return st.st_size;
}

static void parse_config_line(struct wsbr_ctxt *ctxt, const char *filename,
                              int line_no, const char *line)
{
    char garbage; // detect garbage at end of the line
    char str_arg[256];
    char *substr;
    int int_arg;
    int i;

    if (sscanf(line, " %c", &garbage) == EOF) {
        /* blank line*/;
    } else if (sscanf(line, " uart_device = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(ctxt->uart_dev, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
    } else if (sscanf(line, " uart_baudrate = %u %c", &ctxt->uart_baudrate, &garbage) == 1) {
        /* empty */
    } else if (sscanf(line, " uart_rtscts = %s %c", str_arg, &garbage) == 1) {
        ctxt->uart_rtscts = str_to_val(str_arg, valid_booleans);
    } else if (sscanf(line, " cpc_instance = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(ctxt->cpc_instance, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
    } else if (sscanf(line, " cpc_verbose = %s %c", str_arg, &garbage) == 1) {
        ctxt->cpc_verbose = str_to_val(str_arg, valid_booleans);
    } else if (sscanf(line, " tun_device = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(ctxt->tun_dev, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
    } else if (sscanf(line, " tun_autoconf = %s %c", str_arg, &garbage) == 1) {
        ctxt->tun_autoconf = str_to_val(str_arg, valid_booleans);
    } else if (sscanf(line, " network_name = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(ctxt->ws_name, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
    } else if (sscanf(line, " ipv6_prefix = %[0-9a-zA-Z:]/%d %c", str_arg, &int_arg, &garbage) == 2) {
        if (int_arg != 64)
            FATAL(1, "%s:%d: invalid prefix length: %d", filename, line_no, int_arg);
        if (inet_pton(AF_INET6, str_arg, ctxt->ipv6_prefix) != 1)
            FATAL(1, "%s:%d: invalid prefix: %s", filename, line_no, str_arg);
    } else if (sscanf(line, " dhcpv6_server = %[0-9a-zA-Z:] %c", str_arg, &garbage) == 1) {
        parse_netaddr((struct sockaddr_storage *)&ctxt->dhcpv6_server, str_arg);
    } else if (sscanf(line, " certificate = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
        int_arg = read_cert(str_arg, &ctxt->tls_own.cert);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", filename, line_no, str_arg);
        ctxt->tls_own.cert_len = int_arg;
    } else if (sscanf(line, " key = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
        int_arg = read_cert(str_arg, &ctxt->tls_own.key);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", filename, line_no, str_arg);
        ctxt->tls_own.key_len = int_arg;
    } else if (sscanf(line, " authority = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
        int_arg = read_cert(str_arg, &ctxt->tls_ca.cert);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", filename, line_no, str_arg);
        ctxt->tls_ca.cert_len = int_arg;
    } else if (sscanf(line, " radius_server = %s %c", str_arg, &garbage) == 1) {
        parse_netaddr(&ctxt->radius_server, str_arg);
    } else if (sscanf(line, " radius_secret = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(ctxt->radius_secret, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
    } else if (sscanf(line, " trace = %s %c", str_arg, &garbage) == 1) {
        g_enabled_traces = 0;
        substr = strtok(str_arg, ",");
        do {
            g_enabled_traces |= str_to_val(substr, valid_traces);
        } while ((substr = strtok(NULL, ",")));
    } else if (sscanf(line, " domain = %s %c", str_arg, &garbage) == 1) {
        ctxt->ws_domain = str_to_val(str_arg, valid_ws_domains);
    } else if (sscanf(line, " mode = %x %c", &ctxt->ws_mode, &garbage) == 1) {
        for (i = 0; i < ARRAY_SIZE(valid_ws_modes); i++)
            if (valid_ws_modes[i] == ctxt->ws_mode)
                break;
        if (i == ARRAY_SIZE(valid_ws_modes))
            FATAL(1, "%s:%d: invalid mode: %x", filename, line_no, ctxt->ws_mode);
    } else if (sscanf(line, " class = %d %c", &ctxt->ws_class, &garbage) == 1) {
        for (i = 0; i < ARRAY_SIZE(valid_ws_classes); i++)
            if (valid_ws_classes[i] == ctxt->ws_class)
                break;
        if (i == ARRAY_SIZE(valid_ws_classes))
            FATAL(1, "%s:%d: invalid class: %d", filename, line_no, ctxt->ws_class);
    } else if (sscanf(line, " chan0_freq = %u %c", &ctxt->ws_chan0_freq, &garbage) == 1) {
        /* empty */
    } else if (sscanf(line, " chan_spacing = %u %c", &ctxt->ws_chan_spacing, &garbage) == 1) {
        for (i = 0; i < ARRAY_SIZE(valid_ws_chan_spacing); i++)
            if (valid_ws_chan_spacing[i] == ctxt->ws_chan_spacing)
                break;
        if (i == ARRAY_SIZE(valid_ws_chan_spacing))
            FATAL(1, "%s:%d: invalid channel spacing: %d", filename, line_no, ctxt->ws_chan_spacing);
    } else if (sscanf(line, " chan_count = %u %c", &ctxt->ws_chan_count, &garbage) == 1) {
        /* empty */
    } else if (sscanf(line, " allowed_channels = %s %c", str_arg, &garbage) == 1) {
        if (parse_bitmask(ctxt->ws_allowed_channels, ARRAY_SIZE(ctxt->ws_allowed_channels), str_arg) < 0)
            FATAL(1, "%s:%d: invalid range: %s", filename, line_no, str_arg);
    } else if (sscanf(line, " pan_id = %u %c", &ctxt->ws_pan_id, &garbage) == 1) {
        /* empty */
    } else if (sscanf(line, " gtk[%d] = %s %c", &int_arg, str_arg, &garbage) == 2) {
        if (int_arg < 0 || int_arg > 3)
            FATAL(1, "%s:%d: invalid key index: %d", filename, line_no, int_arg);
        if (parse_byte_array(ctxt->ws_gtk[int_arg], 16, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", filename, line_no, str_arg);
        ctxt->ws_gtk_force[int_arg] = true;
    } else if (sscanf(line, " size = %s %c", str_arg, &garbage) == 1) {
        ctxt->ws_size = str_to_val(str_arg, valid_ws_size);
    } else if (sscanf(line, " tx_power = %d %c", &ctxt->tx_power, &garbage) == 1) {
        if (ctxt->tx_power < INT8_MIN || ctxt->tx_power > INT8_MAX)
            FATAL(1, "%s:%d: invalid tx_power: %d", filename, line_no, ctxt->tx_power);
    } else if (sscanf(line, " storage_prefix = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", filename, line_no);
        if (!strcmp(str_arg, "-")) {
            ns_file_system_set_root_path(NULL);
            return;
        }
        ns_file_system_set_root_path(str_arg);
        if (strlen(str_arg) && str_arg[strlen(str_arg) - 1] == '/') {
            if (access(str_arg, W_OK))
                FATAL(1, "%s:%d: %s: %m", filename, line_no, str_arg);
        } else {
            if (access(dirname(str_arg), W_OK))
                FATAL(1, "%s:%d: %s: %m", filename, line_no, str_arg);
        }
    } else if (sscanf(line, " unicast_dwell_interval = %d %c", &ctxt->uc_dwell_interval, &garbage) == 1) {
        if (ctxt->uc_dwell_interval < 15 || ctxt->uc_dwell_interval > 255)
            FATAL(1, "%s:%d: invalid unicast dwell interval: %d", filename, line_no, ctxt->uc_dwell_interval);
    } else if (sscanf(line, " broadcast_interval = %d %c", &ctxt->bc_interval, &garbage) == 1) {
        if (ctxt->bc_interval < 100 || ctxt->bc_interval > 16777215) // UINT24_MAX
            FATAL(1, "%s:%d: invalid broadcast interval: %d", filename, line_no, ctxt->bc_interval);
    } else if (sscanf(line, " broadcast_dwell_interval = %d %c", &ctxt->bc_dwell_interval, &garbage) == 1) {
        if (ctxt->bc_dwell_interval < 100 || ctxt->bc_dwell_interval > 255)
            FATAL(1, "%s:%d: invalid broadcast dwell interval: %d", filename, line_no, ctxt->bc_dwell_interval);
    } else if (sscanf(line, " pmk_lifetime = %d %c", &ctxt->ws_pmk_lifetime, &garbage) == 1) {
        if (ctxt->ws_pmk_lifetime <= 0)
            FATAL(1, "%s:%d: invalid pmk_lifetime: %d", filename, line_no, ctxt->ws_pmk_lifetime);
    } else if (sscanf(line, " ptk_lifetime = %d %c", &ctxt->ws_ptk_lifetime, &garbage) == 1) {
        if (ctxt->ws_ptk_lifetime <= 0)
            FATAL(1, "%s:%d: invalid ptk_lifetime: %d", filename, line_no, ctxt->ws_ptk_lifetime);
    } else if (sscanf(line, " gtk_expire_offset = %d %c", &ctxt->ws_gtk_expire_offset, &garbage) == 1) {
        if (ctxt->ws_gtk_expire_offset <= 0)
            FATAL(1, "%s:%d: invalid gtk_expire_offset: %d", filename, line_no, ctxt->ws_gtk_expire_offset);
    } else if (sscanf(line, " gtk_new_activation_time = %d %c", &ctxt->ws_gtk_new_activation_time, &garbage) == 1) {
        if (ctxt->ws_gtk_new_activation_time <= 1)
            FATAL(1, "%s:%d: invalid gtk_new_activation_time: %d", filename, line_no, ctxt->ws_gtk_new_activation_time);
    } else if (sscanf(line, " gtk_new_install_required = %d %c", &ctxt->ws_gtk_new_install_required, &garbage) == 1) {
        if (ctxt->ws_gtk_new_install_required <= 0 || ctxt->ws_gtk_new_install_required > 100)
            FATAL(1, "%s:%d: invalid gtk_new_install_required: %d", filename, line_no, ctxt->ws_gtk_new_install_required);
    } else if (sscanf(line, " revocation_lifetime_reduction = %d %c", &ctxt->ws_revocation_lifetime_reduction, &garbage) == 1) {
        if (ctxt->ws_revocation_lifetime_reduction <= 0)
            FATAL(1, "%s:%d: invalid revocation_lifetime_reduction: %d", filename, line_no, ctxt->ws_revocation_lifetime_reduction);
    } else if (sscanf(line, " gtk_max_mismatch = %d %c", &ctxt->ws_gtk_max_mismatch, &garbage) == 1) {
        if (ctxt->ws_gtk_max_mismatch <= 0)
            FATAL(1, "%s:%d: invalid gtk_max_mismatch: %d", filename, line_no, ctxt->ws_gtk_max_mismatch);
    } else if (sscanf(line, " allowed_mac64 = %s %c", str_arg, &garbage) == 1) {
        if (ctxt->ws_denied_mac_address_count > 0)
            FATAL(1, "%s:%d: allowed_mac64 and denied_mac64 are exclusive", filename, line_no);
        if (ctxt->ws_allowed_mac_address_count >= ARRAY_SIZE(ctxt->ws_allowed_mac_addresses))
            FATAL(1, "%s:%d: maximum number of allowed MAC addresses reached", filename, line_no);
        if (parse_byte_array(ctxt->ws_allowed_mac_addresses[ctxt->ws_allowed_mac_address_count], 8, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", filename, line_no, str_arg);
        ctxt->ws_allowed_mac_address_count++;
    } else if (sscanf(line, " denied_mac64 = %s %c", str_arg, &garbage) == 1) {
        if (ctxt->ws_allowed_mac_address_count > 0)
            FATAL(1, "%s:%d: allowed_mac64 and denied_mac64 are exclusive", filename, line_no);
        if (ctxt->ws_denied_mac_address_count >= ARRAY_SIZE(ctxt->ws_denied_mac_addresses))
            FATAL(1, "%s:%d: maximum number of denied MAC addresses reached", filename, line_no);
        if (parse_byte_array(ctxt->ws_denied_mac_addresses[ctxt->ws_denied_mac_address_count], 8, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", filename, line_no, str_arg);
        ctxt->ws_denied_mac_address_count++;
    } else if (sscanf(line, " regional_regulation = %s %c", str_arg, &garbage) == 1) {
        ctxt->ws_regional_regulation = str_to_val(str_arg, valid_ws_regional_regulations);
    } else if (sscanf(line, " use_tap = %s %c", str_arg, &garbage) == 1) {
        ctxt->tun_use_tap = str_to_val(str_arg, valid_booleans);
    } else {
        FATAL(1, "%s:%d: syntax error: '%s'", filename, line_no, line);
    }
}

static void parse_config_file(struct wsbr_ctxt *ctxt, const char *filename)
{
    FILE *f = fopen(filename, "r");
    int line_no = 0;
    char line[256];
    int len;

    if (!f)
        FATAL(1, "%s: %m", filename);
    while (fgets(line, sizeof(line), f)) {
        line_no++;
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';
        if (len <= 0)
            continue;
        *(strchrnul(line, '#')) = '\0';
        parse_config_line(ctxt, filename, line_no, line);
    }
    fclose(f);
}

void parse_commandline(struct wsbr_ctxt *ctxt, int argc, char *argv[],
                       void (*print_help)(FILE *stream))
{
    const char *opts_short = "u:sF:o:t:T:n:d:m:c:S:K:C:A:b:Hh";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "list-rf-configs", no_argument,   0,  'l' },
        { "tun",         required_argument, 0,  't' },
        { "trace",       required_argument, 0,  'T' },
        { "network",     required_argument, 0,  'n' },
        { "domain",      required_argument, 0,  'd' },
        { "mode",        required_argument, 0,  'm' },
        { "class",       required_argument, 0,  'c' },
        { "size",        required_argument, 0,  'S' },
        { "key",         required_argument, 0,  'K' },
        { "cert",        required_argument, 0,  'C' },
        { "certificate", required_argument, 0,  'C' },
        { "authority",   required_argument, 0,  'A' },
        { "baudrate",    required_argument, 0,  'b' },
        { "hardflow",    no_argument,       0,  'H' },
        { "help",        no_argument,       0,  'h' },
        { 0,             0,                 0,   0  }
    };
    char *end_ptr;
    int opt, i, ret;
    char *tag;

    ctxt->uart_baudrate = 115200;
    ctxt->tun_autoconf = true;
    ctxt->ws_class = 0;
    ctxt->ws_domain = REG_DOMAIN_UNDEF;
    ctxt->ws_mode = 0;
    ctxt->ws_size = NETWORK_SIZE_SMALL;
    ctxt->ws_pan_id = -1;
    ctxt->tx_power = 20;
    ctxt->uc_dwell_interval = WS_FHSS_UC_DWELL_INTERVAL;
    ctxt->bc_interval = WS_FHSS_BC_INTERVAL;
    ctxt->bc_dwell_interval = WS_FHSS_BC_DWELL_INTERVAL;
    ctxt->ws_allowed_mac_address_count = 0;
    ctxt->ws_denied_mac_address_count = 0;
    ctxt->ws_regional_regulation = 0,
    ns_file_system_set_root_path("/var/lib/wsbrd/");
    memset(ctxt->ws_allowed_channels, 0xFF, sizeof(ctxt->ws_allowed_channels));
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                parse_config_file(ctxt, optarg);
                break;
            case '?':
                print_help(stderr);
                exit(1);
                break;
            default:
                break;
        }
    }
    optind = 1; /* reset getopt */
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                break;
            case 'u':
                strncpy(ctxt->uart_dev, optarg, sizeof(ctxt->uart_dev) - 1);
                break;
            case 'o':
                parse_config_line(ctxt, "command line", 0, optarg);
                break;
            case 'l':
                ctxt->list_rf_configs = true;
                break;
            case 't':
                strncpy(ctxt->tun_dev, optarg, sizeof(ctxt->tun_dev) - 1);
                break;
            case 'T':
                tag = strtok(optarg, ",");
                do {
                    g_enabled_traces |= str_to_val(tag, valid_traces);
                } while ((tag = strtok(NULL, ",")));
                break;
            case 'n':
                strncpy(ctxt->ws_name, optarg, sizeof(ctxt->ws_name) - 1);
                break;
            case 'd':
                ctxt->ws_domain = str_to_val(optarg, valid_ws_domains);
                break;
            case 'm':
                ctxt->ws_mode = strtoul(optarg, &end_ptr, 16);
                if (*end_ptr)
                    FATAL(1, "invalid mode: %s", optarg);
                for (i = 0; i < ARRAY_SIZE(valid_ws_modes); i++)
                    if (valid_ws_modes[i] == ctxt->ws_mode)
                        break;
                if (i == ARRAY_SIZE(valid_ws_modes))
                    FATAL(1, "invalid mode: %s", optarg);
                break;
            case 'c':
                ctxt->ws_class = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr)
                    FATAL(1, "invalid class: %s", optarg);
                for (i = 0; i < ARRAY_SIZE(valid_ws_classes); i++)
                    if (valid_ws_classes[i] == ctxt->ws_class)
                        break;
                if (i == ARRAY_SIZE(valid_ws_classes))
                    FATAL(1, "invalid class: %s", optarg);
                break;
            case 'S':
                ctxt->ws_size = str_to_val(optarg, valid_ws_size);
                break;
            case 'K':
                ret = read_cert(optarg, &ctxt->tls_own.key);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                ctxt->tls_own.key_len = ret;
                break;
            case 'C':
                ret = read_cert(optarg, &ctxt->tls_own.cert);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                ctxt->tls_own.cert_len = ret;
                break;
            case 'A':
                ret = read_cert(optarg, &ctxt->tls_ca.cert);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                ctxt->tls_ca.cert_len = ret;
                break;
            case 'b':
                FATAL(1, "deprecated option: -b/--baudrate");
                break;
            case 'H':
                FATAL(1, "deprecated option: -H/--hardflow");
                break;
            case 'h':
                print_help(stdout);
                exit(0);
                break;
            default:
                BUG(); /* Cannot happen */
                break;
        }
    }
    if (optind != argc)
        FATAL(1, "unexpected argument: %s", argv[optind]);
    if (!ctxt->ws_name[0])
        FATAL(1, "missing \"network_name\" parameter");
    if (ctxt->ws_chan0_freq || ctxt->ws_chan_spacing || ctxt->ws_chan_count) {
        if (ctxt->ws_domain != REG_DOMAIN_UNDEF || ctxt->ws_class)
            FATAL(1, "custom channel plan is exclusive with \"domain\" and \"class\"");
        if (!ctxt->ws_chan0_freq)
            FATAL(1, "custom channel plan need \"chan0_freq\"");
        if (!ctxt->ws_chan_spacing)
            FATAL(1, "custom channel plan need \"chan_spacing\"");
        if (!ctxt->ws_chan_count)
            FATAL(1, "custom channel plan need \"chan_count\"");
    } else {
        if (ctxt->ws_domain == REG_DOMAIN_UNDEF)
            FATAL(1, "missing \"domain\" parameter");
        if (!ctxt->ws_class)
            FATAL(1, "missing \"class\" parameter");
    }
    if (ctxt->ws_domain == REG_DOMAIN_JP && ctxt->ws_regional_regulation != REG_REGIONAL_ARIB)
        WARN("Japanese regulation domain used without ARIB regional regulation");
    if (ctxt->ws_domain != REG_DOMAIN_JP && ctxt->ws_regional_regulation == REG_REGIONAL_ARIB)
        FATAL(1, "ARIB is only supported with Japanese regulation domain");
    if (!ctxt->ws_mode)
        FATAL(1, "missing \"mode\" parameter");
    if (ctxt->ws_mode & OPERATING_MODE_PHY_MODE_ID_BIT)
        ctxt->ws_phy_mode_id = ctxt->ws_mode & OPERATING_MODE_PHY_MODE_ID_MASK;
    if (ctxt->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_BIT)
        ctxt->ws_chan_plan_id = ctxt->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_MASK;
    if (ctxt->bc_interval < ctxt->bc_dwell_interval)
        FATAL(1, "broadcast interval %d can't be lower than broadcast dwell interval %d", ctxt->bc_interval, ctxt->bc_dwell_interval);
    if (!ctxt->uart_dev[0] && !ctxt->cpc_instance[0])
        FATAL(1, "missing \"uart_device\" (or \"cpc_instance\") parameter");
    if (ctxt->uart_dev[0] && ctxt->cpc_instance[0])
        FATAL(1, "\"uart_device\" and \"cpc_instance\" are exclusive %s", ctxt->uart_dev);
    if (ctxt->radius_server.ss_family == AF_UNSPEC) {
        if (!ctxt->tls_own.key)
            FATAL(1, "missing \"key\" (or \"radius_server\") parameter");
        if (!ctxt->tls_own.cert)
            FATAL(1, "missing \"certificate\" (or \"radius_server\") parameter");
        if (!ctxt->tls_ca.cert)
            FATAL(1, "missing \"authority\" (or \"radius_server\") parameter");
    } else {
        if (ctxt->tls_own.cert_len != 0 || ctxt->tls_own.key_len != 0 || ctxt->tls_ca.cert_len != 0)
            WARN("ignore certificates and key since an external radius server is in use");
    }
#ifdef HAVE_WS_BORDER_ROUTER
    if (ctxt->dhcpv6_server.sin6_family == AF_INET6) {
        if (memcmp(ctxt->ipv6_prefix, ADDR_UNSPECIFIED, 16) != 0)
            WARN("ipv6_prefix will be ignored because you specified a dhcpv6_server address");
    } else if (ctxt->dhcpv6_server.sin6_family == AF_INET) {
        FATAL(1, "dhcpv6_server does not support IPv4 server");
    } else {
        if (!memcmp(ctxt->ipv6_prefix, ADDR_UNSPECIFIED, 16))
            FATAL(1, "You must specify a ipv6_prefix");
    }
#else
    if (!ctxt->uart_dev[0])
        FATAL(1, "missing \"uart_device\" parameter");
    if (memcmp(ctxt->ipv6_prefix, ADDR_UNSPECIFIED, 16))
        WARN("ipv6_prefix is ignored");
#endif
}
