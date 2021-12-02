/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/stat.h>

#include "mbed-client-libservice/ip6string.h"
#include "nanostack/source/6LoWPAN/ws/ws_common_defines.h"
#include "nanostack/ws_management_api.h"
#include "nanostack/ns_file_system.h"
#include "host-common/os_types.h"
#include "host-common/utils.h"
#include "host-common/log.h"
#include "named_values.h"
#include "wsbr.h"

static const int valid_ws_modes[] = {
    0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05
};

void print_help_br(FILE *stream, int exit_code) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsbrd [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif\n");
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
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM od DER\n");
    fprintf(stream, "  format.\n");
    fprintf(stream, "  -K, --key=FILE         Private key (keep it secret)\n");
    fprintf(stream, "  -C, --certificate=FILE Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE   Certificate of the authority (CA) (shared with all devices of the\n");
    fprintf(stream, "                           network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
    exit(exit_code);
}

void print_help_node(FILE *stream, int exit_code) {
    fprintf(stream, "\n");
    fprintf(stream, "Simulate a Wi-SUN node\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsnode [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif\n");
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
    exit(exit_code);
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

static int set_bitmask(int shift, uint32_t *out, int size)
{
    int word_nr = shift / 32;
    int bit_nr = shift % 32;

    if (word_nr >= size)
        return -1;
    out[word_nr] |= 1 << bit_nr;
    return 0;
}

static int parse_bitmask(char *str, uint32_t *out, int size)
{
    char *range;
    char *endptr;
    unsigned long cur, end;

    memset(out, 0, size * sizeof(uint32_t));
    range = strtok(str, ",");
    do {
        cur = strtoul(range, &endptr, 0);
        if (*endptr == '-') {
            range = endptr + 1;
            end = strtol(range, &endptr, 0);
        } else {
            end = cur;
        }
        if (*endptr != '\0')
            return -1;
        if (cur > end)
            return -1;
        for (; cur <= end; cur++)
            if (set_bitmask(cur, out, size) < 0)
                return -1;
    } while ((range = strtok(NULL, ",")));
    return 0;
}

static int parse_escape_sequences(char *out, char *in)
{
    char tmp[3], *end_ptr;
    int i, j;

    j = 0;
    for (i = 0; in[i]; ) {
        if (in[i] == '\\') {
            if (in[i + 1] != 'x')
                return -1;
            tmp[0] = in[i + 2];
            tmp[1] = in[i + 3];
            tmp[2] = '\0';
            out[j++] = strtol(tmp, &end_ptr, 16);
            if (*end_ptr)
                return -1;
            i += 4;
        } else {
            out[j++] = in[i++];
        }
    }
    out[j++] = '\0';
    return 0;
}

static int parse_byte_array(const char *in, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        if (in[2] != '\0' && in[2] != ':')
            return -1;
        if (sscanf(in, "%hhx", out + i) != 1)
            return -2;
        in += 3;
    }
    if (in[-1] != '\0')
        return -3;
    return 0;
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
        if (!stoip6(str_arg, strlen(str_arg), ctxt->ipv6_prefix))
            FATAL(1, "%s:%d: invalid prefix: %s", filename, line_no, str_arg);
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
        if (ctxt->ws_class > 4)
            FATAL(1, "%s:%d: invalid operating class: %d", filename, line_no, ctxt->ws_class);
    } else if (sscanf(line, " allowed_channels = %s %c", str_arg, &garbage) == 1) {
        if (parse_bitmask(str_arg, ctxt->ws_allowed_channels, ARRAY_SIZE(ctxt->ws_allowed_channels)) < 0)
            FATAL(1, "%s:%d: invalid range: %s", filename, line_no, str_arg);
    } else if (sscanf(line, " pan_id = %u %c", &ctxt->ws_pan_id, &garbage) == 1) {
        /* empty */
    } else if (sscanf(line, " gtk[%d] = %s %c", &int_arg, str_arg, &garbage) == 2) {
        if (int_arg < 0 || int_arg > 3)
            FATAL(1, "%s:%d: invalid key index: %d", filename, line_no, int_arg);
        if (parse_byte_array(str_arg, ctxt->ws_gtk[int_arg], 16))
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
        if (parse_byte_array(str_arg, ctxt->ws_allowed_mac_addresses[ctxt->ws_allowed_mac_address_count], 8))
            FATAL(1, "%s:%d: invalid key: %s", filename, line_no, str_arg);
        ctxt->ws_allowed_mac_address_count++;
    } else if (sscanf(line, " denied_mac64 = %s %c", str_arg, &garbage) == 1) {
        if (ctxt->ws_allowed_mac_address_count > 0)
            FATAL(1, "%s:%d: allowed_mac64 and denied_mac64 are exclusive", filename, line_no);
        if (ctxt->ws_denied_mac_address_count >= ARRAY_SIZE(ctxt->ws_denied_mac_addresses))
            FATAL(1, "%s:%d: maximum number of denied MAC addresses reached", filename, line_no);
        if (parse_byte_array(str_arg, ctxt->ws_denied_mac_addresses[ctxt->ws_denied_mac_address_count], 8))
            FATAL(1, "%s:%d: invalid key: %s", filename, line_no, str_arg);
        ctxt->ws_denied_mac_address_count++;
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
                       void (*print_help)(FILE *stream, int exit_code))
{
    const char *opts_short = "u:sF:o:t:T:n:d:m:c:S:K:C:A:b:Hh";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
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
    ctxt->ws_class = 1;
    ctxt->ws_domain = -1;
    ctxt->ws_mode = 0x1b;
    ctxt->ws_size = NETWORK_SIZE_SMALL;
    ctxt->ws_pan_id = -1;
    ctxt->tx_power = 20;
    ctxt->uc_dwell_interval = WS_FHSS_UC_DWELL_INTERVAL;
    ctxt->bc_interval = WS_FHSS_BC_INTERVAL;
    ctxt->bc_dwell_interval = WS_FHSS_BC_DWELL_INTERVAL;
    ctxt->ws_allowed_mac_address_count = 0;
    ctxt->ws_denied_mac_address_count = 0;
    ns_file_system_set_root_path("/var/lib/wsbrd/");
    memset(ctxt->ws_allowed_channels, 0xFF, sizeof(ctxt->ws_allowed_channels));
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                parse_config_file(ctxt, optarg);
                break;
            case '?':
                print_help(stderr, 1);
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
                if (*end_ptr || ctxt->ws_class > 3)
                    FATAL(1, "invalid operating class: %s", optarg);
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
                print_help(stdout, 0);
                break;
            default:
                BUG(); /* Cannot happen */
                break;
        }
    }
    if (optind != argc)
        FATAL(1, "Unexpected argument: %s", argv[optind]);
    if (!ctxt->ws_name[0])
        FATAL(1, "You must specify a network name (--network)");
    if (!ctxt->tls_own.key)
        FATAL(1, "You must specify a key (--key)");
    if (!ctxt->tls_own.cert)
        FATAL(1, "You must specify a certificate (--certificate)");
    if (!ctxt->tls_ca.cert)
        FATAL(1, "You must specify a certificate authority (--authority)");
    if (ctxt->ws_domain == -1)
        FATAL(1, "You must specify a regulation domain (--domain)");
    if (ctxt->bc_interval < ctxt->bc_dwell_interval)
        FATAL(1, "broadcast interval %d can't be lower than broadcast dwell interval %d", ctxt->bc_interval, ctxt->bc_dwell_interval);
    if (!ctxt->uart_dev[0])
        FATAL(1, "You must specify a UART device");
}
