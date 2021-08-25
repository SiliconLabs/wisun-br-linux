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
#include <sys/stat.h>

#include "nanostack/ws_management_api.h"
#include "host-common/os_types.h"
#include "host-common/bus_uart.h"
#include "host-common/bus_spi.h"
#include "host-common/utils.h"
#include "host-common/log.h"
#include "wsbr.h"

static const int valid_ws_modes[] = {
    0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05
};

static const struct {
    char *name;
    int val;
} valid_ws_domains[] = {
    { "WW", REG_DOMAIN_WW }, // World wide
    { "NA", REG_DOMAIN_NA }, // North America
    { "JP", REG_DOMAIN_JP }, // Japan
    { "EU", REG_DOMAIN_EU }, // European Union
    { "CH", REG_DOMAIN_CH }, // China
    { "IN", REG_DOMAIN_IN }, // India
    { "MX", REG_DOMAIN_MX }, //
    { "BZ", REG_DOMAIN_BZ }, // Brazil
    { "AZ", REG_DOMAIN_AZ }, // Australia
    { "NZ", REG_DOMAIN_NZ }, // New zealand
    { "KR", REG_DOMAIN_KR }, // Korea
    { "PH", REG_DOMAIN_PH }, //
    { "MY", REG_DOMAIN_MY }, //
    { "HK", REG_DOMAIN_HK }, //
    { "SG", REG_DOMAIN_SG }, // band 866-869
    { "TH", REG_DOMAIN_TH }, //
    { "VN", REG_DOMAIN_VN }, //
    { "SG", REG_DOMAIN_SG_H }, // band 920-925
};

static const struct {
    char *name;
    int val;
} valid_ws_size[] = {
    { "AUTO",   NETWORK_SIZE_AUTOMATIC },
    { "CERT",   NETWORK_SIZE_CERTIFICATE },
    { "SMALL",  NETWORK_SIZE_SMALL },
    { "S",      NETWORK_SIZE_SMALL },
    { "MEDIUM", NETWORK_SIZE_MEDIUM },
    { "M",      NETWORK_SIZE_MEDIUM },
    { "LARGE",  NETWORK_SIZE_LARGE },
    { "L",      NETWORK_SIZE_LARGE },
    { "XLARGE", NETWORK_SIZE_XLARGE },
    { "XL",     NETWORK_SIZE_XLARGE },
};

static void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsbrd -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  wsbrd -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  wsbrd -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u                    Use UART bus\n");
    fprintf(stream, "  -s                    Use SPI bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU, NA, JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b, 2a, 2b, 3 (default), 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1, 2 (default) or 3\n");
    fprintf(stream, "  -S, --size=SIZE       Optimize network timings considering the number of expected nodes on\n");
    fprintf(stream, "                          the network. Valid values: AUTO (default), CERT (development and\n");
    fprintf(stream, "                          certification), S (< 100), M (100-800), L (800-2500), XL (> 2500)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM\n");
    fprintf(stream, "  or DER format.\n");
    fprintf(stream, "  -K, --key=FILE        Private key (keep it secret)\n");
    fprintf(stream, "  -C, --cert=FILE       Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE  Certificate of the authority (CA) (shared with all devices\n");
    fprintf(stream, "                        of the network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "UART options\n");
    fprintf(stream, "  -b, --baudrate=BAUDRATE  UART baudrate: 9600, 19200, 38400, 57600, 115200 (default),\n");
    fprintf(stream, "                           230400, 460800, 921600\n");
    fprintf(stream, "  -H, --hardflow           Hardware CTS/RTS flow control (default: disabled)\n");
    fprintf(stream, "\n");
    fprintf(stream, "SPI options:\n");
    fprintf(stream, "  -f, --frequency=FREQUENCY  Clock frequency (default: 1000000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -H -C cert.pem -A ca.pem -K key.pem\n");
    fprintf(stream, "  wsbrd -s -n my_network -C cert.pem -A ca.pem -K key.pem /dev/spi1.1 141\n");
    fprintf(stream, "  wsbrd -s /dev/spi1.1 /sys/class/gpio/gpio141/value -C cert.pem -A ca.pem -K key.pem\n");
    exit(exit_code);
}

static size_t read_cert(const char *filename, const uint8_t **ptr)
{
    uint8_t *tmp;
    int fd, ret;
    struct stat st;

    fd = open(filename, O_RDONLY);
    FATAL_ON(fd < 0, 1, "%s: %d %m", filename, fd);
    ret = fstat(fd, &st);
    FATAL_ON(ret < 0, 1, "fstat: %s: %m", filename);

    /* See https://github.com/ARMmbed/mbedtls/issues/3896 and
     * mbedtls_x509_crt_parse()
     */
    tmp = malloc(st.st_size + 1);
    tmp[st.st_size] = 0;
    ret = read(fd, tmp, st.st_size);
    FATAL_ON(ret != st.st_size, 1, "read: %s: %m", filename);
    close(fd);
    *ptr = tmp;

    if (strstr((char *)tmp, "-----BEGIN CERTIFICATE-----"))
        return st.st_size + 1;
    else
        return st.st_size;
}

static void read_config_file(struct wsbr_ctxt *ctxt, const char *filename)
{
    FILE *f = fopen(filename, "r");
    int line_no = 0;
    char line[256];
    char tmp[256];
    char garbage; // detect garbage at end of the line
    int len;
    int i;

    if (!f)
        FATAL(1, "%s: %m", filename);
    while (fgets(line, sizeof(line), f)) {
        line_no++;
        len = strlen(line) - 1;
        if (len < 0)
            continue;
        if (line[len] == '\n')
            line[len--] = '\0';
        if (line[len] == '\r')
            line[len--] = '\0';
        *(strchrnul(line, '#')) = '\0';
        if (sscanf(line, " %c", &garbage) == EOF) {
            /* blank line*/;
        } else if (sscanf(line, " network_name = %s %c", ctxt->ws_name, &garbage) == 1) {
            /* nothing to do */;
        } else if (sscanf(line, " certificate = %s %c", tmp, &garbage) == 1) {
            ctxt->tls_own.cert_len = read_cert(tmp, &ctxt->tls_own.cert);
        } else if (sscanf(line, " key = %s %c", tmp, &garbage) == 1) {
            ctxt->tls_own.key_len = read_cert(tmp, &ctxt->tls_own.key);
        } else if (sscanf(line, " authority = %s %c", tmp, &garbage) == 1) {
            ctxt->tls_ca.cert_len = read_cert(tmp, &ctxt->tls_ca.cert);
        } else if (sscanf(line, " domain = %s %c", tmp, &garbage) == 1) {
            ctxt->ws_domain = -1;
            for (i = 0; i < ARRAY_SIZE(valid_ws_domains); i++) {
                if (!strcmp(valid_ws_domains[i].name, tmp)) {
                    ctxt->ws_domain = valid_ws_domains[i].val;
                    break;
                }
            }
            if (ctxt->ws_domain < 0)
                FATAL(1, "%s:%d: invalid domain: %s", filename, line_no, tmp);
        } else if (sscanf(line, " mode = %x %c", &ctxt->ws_mode, &garbage) == 1) {
            for (i = 0; i < ARRAY_SIZE(valid_ws_modes); i++)
                if (valid_ws_modes[i] == ctxt->ws_mode)
                    break;
            if (i == ARRAY_SIZE(valid_ws_modes))
                FATAL(1, "%s:%d: invalid mode: %x", filename, line_no, ctxt->ws_mode);
        } else if (sscanf(line, " class = %d %c", &ctxt->ws_class, &garbage) == 1) {
            if (ctxt->ws_class > 3)
                FATAL(1, "%s:%d: invalid operating class: %d", filename, line_no, ctxt->ws_class);
        } else if (sscanf(line, " size = %s %c", tmp, &garbage) == 1) {
                ctxt->ws_size = -1;
                for (i = 0; i < ARRAY_SIZE(valid_ws_size); i++) {
                    if (!strcasecmp(valid_ws_size[i].name, tmp)) {
                        ctxt->ws_size = valid_ws_size[i].val;
                        break;
                    }
                }
                if (ctxt->ws_size < 0)
                   FATAL(1, "%s:%d: invalid network size: %s", filename, line_no, tmp);
        } else {
            FATAL(1, "%s:%d: syntax error: '%s'", filename, line_no, line);
        }
    }
}

void parse_commandline(struct wsbr_ctxt *ctxt, int argc, char *argv[])
{
    const char *opts_short = "usF:t:n:d:m:c:S:K:C:A:b:f:Hh";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "tun",         required_argument, 0,  't' },
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
        { "frequency",   required_argument, 0,  'f' },
        { "hardflow",    no_argument,       0,  'H' },
        { "help",        no_argument,       0,  'h' },
        { 0,             0,                 0,   0  }
    };
    char *end_ptr;
    char bus = 0;
    int baudrate = 115200;
    int frequency = 1000000;
    bool hardflow = false;
    int opt, i;

    ctxt->ws_class = 1;
    ctxt->ws_domain = -1;
    ctxt->ws_mode = 0x1a;
    ctxt->ws_size = NETWORK_SIZE_AUTOMATIC;
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                read_config_file(ctxt, optarg);
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
            case 's':
                if (bus)
                    print_help(stderr, 1);
                bus = opt;
                break;
            case 't':
                strncpy(ctxt->tun_dev, optarg, sizeof(ctxt->tun_dev) - 1);
                break;
            case 'n':
                strncpy(ctxt->ws_name, optarg, sizeof(ctxt->ws_name) - 1);
                break;
            case 'd':
                ctxt->ws_domain = -1;
                for (i = 0; i < ARRAY_SIZE(valid_ws_domains); i++) {
                    if (!strcmp(valid_ws_domains[i].name, optarg)) {
                        ctxt->ws_domain = valid_ws_domains[i].val;
                        break;
                    }
                }
                if (ctxt->ws_domain < 0)
                    FATAL(1, "invalid domain: %s", optarg);
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
                ctxt->ws_size = -1;
                for (i = 0; i < ARRAY_SIZE(valid_ws_size); i++) {
                    if (!strcasecmp(valid_ws_size[i].name, optarg)) {
                        ctxt->ws_size = valid_ws_size[i].val;
                        break;
                    }
                }
                if (ctxt->ws_size < 0)
                    FATAL(1, "invalid network size: %s", optarg);
                break;
            case 'K':
                if (ctxt->tls_own.key)
                    FATAL(1, "--key can be specified only one time");
                ctxt->tls_own.key_len = read_cert(optarg, &ctxt->tls_own.key);
                break;
            case 'C':
                if (ctxt->tls_own.cert)
                    FATAL(1, "--cert can be specified only one time");
                ctxt->tls_own.cert_len = read_cert(optarg, &ctxt->tls_own.cert);
                break;
            case 'A':
                if (ctxt->tls_ca.cert)
                    FATAL(1, "--authority can be specified only one time");
                ctxt->tls_ca.cert_len = read_cert(optarg, &ctxt->tls_ca.cert);
                break;
            case 'b':
                baudrate = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr)
                    FATAL(1, "invalid bitrate: %s", optarg);
                break;
            case 'f':
                frequency = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr)
                    FATAL(1, "invalid frequency: %s", optarg);
                break;
            case 'H':
                hardflow = true;
                break;
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
            default:
                print_help(stderr, 1);
                break;
        }
    }
    if (!ctxt->ws_name[0])
        FATAL(1, "You must specify --name");
    if (!ctxt->tls_own.key)
        FATAL(1, "You must specify --key");
    if (!ctxt->tls_own.cert)
        FATAL(1, "You must specify --cert");
    if (!ctxt->tls_ca.cert)
        FATAL(1, "You must specify --authority");
    if (ctxt->ws_domain == -1)
        FATAL(1, "You must specify --domain");
    if (bus == 's') {
        if (argc != optind + 2)
            print_help(stderr, 1);
        ctxt->rcp_tx = spi_tx;
        ctxt->rcp_rx = spi_rx;
        ctxt->os_ctxt->data_fd = spi_open(argv[optind + 0], frequency, 0);
        ctxt->os_ctxt->trig_fd = gpio_open(argv[optind + 1], false);
        ctxt->os_ctxt->spi_recv_window = UINT16_MAX;
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->rcp_tx = uart_tx;
        ctxt->rcp_rx = uart_rx;
        ctxt->os_ctxt->data_fd = uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    } else {
        print_help(stderr, 1);
    }
}
