#include <stdbool.h>
#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include "host-common/log.h"
#include "host-common/utils.h"

struct ctxt {
    struct sockaddr_un addr;
    uint32_t node_graph[256][256 / 32];
};

static int bitmap_get(int shift, uint32_t *in, int size)
{
    int word_nr = shift / 32;
    int bit_nr = shift % 32;

    if (word_nr >= size)
        return -1;
    return !!(in[word_nr] & (1 << bit_nr));
}

static int bitmap_set(int shift, uint32_t *out, int size)
{
    int word_nr = shift / 32;
    int bit_nr = shift % 32;

    if (word_nr >= size)
        return -1;
    out[word_nr] |= 1 << bit_nr;
    return 0;
}

static int bitmap_parse(char *str, uint32_t *out, int size)
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
            if (bitmap_set(cur, out, size) < 0)
                return -1;
    } while ((range = strtok(NULL, ",")));
    return 0;
}

static void graph_apply_mask(uint32_t node_graph[256][256 / 32], uint32_t mask[256 / 32])
{
    int i, j;

    for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++)
            if (i != j
                && bitmap_get(i, mask, 256 / 32)
                && bitmap_get(j, mask, 256 / 32))
                bitmap_set(j, node_graph[i], 256 / 32);
}

static int graph_get_num_nodes(struct ctxt *ctxt)
{
    int max = 0;
    int i, j;

    for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++)
            if (bitmap_get(j, ctxt->node_graph[i], 256 / 32))
                max = i;
    return max + 1;
}

static void graph_dump(struct ctxt *ctxt)
{
    int max = graph_get_num_nodes(ctxt);
    int i, j;

    for (i = 0; i < max; i++) {
        printf("%02x ", i);
        for (j = 0; j < max; j++)
            printf("%s", bitmap_get(j, ctxt->node_graph[i], 256 / 32) ? "x" : "-");
        printf("\n");
    }
}

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "broadcast server to create networks of wshwsim\n");
    exit(exit_code);
}

void parse_commandline(struct ctxt *ctxt, int argc, char *argv[])
{
    const char *opts_short = "hg:";
    static const struct option opts_long[] = {
        { "group", required_argument, 0,  'g' },
        { "help",  no_argument,       0,  'h' },
        { 0,       0,                 0,   0  }
    };
    uint32_t mask[256 / 32];
    int opt;

    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'g':
                bitmap_parse(optarg, mask, 256 / 32);
                graph_apply_mask(ctxt->node_graph, mask);
                break;
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
                print_help(stderr, 1);
                break;
            default:
                break;
        }
    }
    if (!graph_get_num_nodes(ctxt))
        memset(ctxt->node_graph, 0xFF, sizeof(ctxt->node_graph));
    if (optind >= argc)
        FATAL(1, "Expected argument: socket path");
    if (optind + 1 < argc)
        FATAL(1, "Too many arguments argument: %s", argv[optind + 1]);
    FATAL_ON(strlen(argv[optind]) >= sizeof(ctxt->addr.sun_path), 1);
    strcpy(ctxt->addr.sun_path, argv[optind]);
}

static void broadcast(int sender_fd, struct pollfd *fds, int fds_len, void *buf, int buf_len)
{
    int j;
    int ret;

    for (j = 0; j < fds_len; j++) {
        if (fds[j].fd >= 0 && fds[j].fd != sender_fd) {
            ret = write(fds[j].fd, buf, buf_len);
            FATAL_ON(ret != buf_len, 1, "write: %m");
        }
    }
}

int main(int argc, char **argv)
{
    char buf[4096];
    int i;
    int on = 1;
    int ret, len;
    struct pollfd fds[256] = { };
    struct ctxt ctxt = {
        .addr.sun_family = AF_UNIX
    };

    parse_commandline(&ctxt, argc, argv);
    for (i = 0; i < ARRAY_SIZE(fds); i++)
        fds[i].fd = -1;

    fds[0].events = POLLIN;
    fds[0].fd = socket(AF_UNIX, SOCK_SEQPACKET, 0); // use SOCK_SEQPACKET or SOCK_STREAM
    FATAL_ON(fds[0].fd < 0, 1, "socket: %s: %m", ctxt.addr.sun_path);
    ret = setsockopt(fds[0].fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    FATAL_ON(ret < 0, 1, "setsockopt: %s: %m", ctxt.addr.sun_path);
    ret = bind(fds[0].fd, (struct sockaddr *)&ctxt.addr, sizeof(ctxt.addr));
    FATAL_ON(ret < 0, 1, "bind: %s: %m", ctxt.addr.sun_path);
    ret = listen(fds[0].fd, 4096);
    FATAL_ON(ret < 0, 1, "listen: %s: %m", ctxt.addr.sun_path);

    while (true) {
        ret = poll(fds, ARRAY_SIZE(fds), -1);
        FATAL_ON(ret < 0, 1, "poll: %m");
        if (fds[0].revents) {
            for (i = 0; i < ARRAY_SIZE(fds); i++) {
                if (fds[i].fd == -1) {
                    fds[i].events = POLLIN;
                    fds[i].fd = accept(fds[0].fd, NULL, NULL);
                    DEBUG("Connect fd %d", fds[i].fd);
                    FATAL_ON(fds[i].fd < 0, 1, "accept: %m");
                    break;
                }
            }
        }
        for (i = 1; i < ARRAY_SIZE(fds); i++) {
            if (fds[i].revents) {
                len = read(fds[i].fd, buf, sizeof(buf));
                if (len < 1) {
                    DEBUG("Disconnect fd %d", fds[i].fd);
                    close(fds[i].fd);
                    fds[i].fd = -1;
                    fds[i].events = 0;
                } else {
                    broadcast(fds[i].fd, fds + 1, ARRAY_SIZE(fds) - 1, buf, len);
                    if (len == 6 && buf[0] == 'x' && buf[1] == 'x') {
                        len = read(fds[i].fd, buf, sizeof(buf));
                        broadcast(fds[i].fd, fds + 1, ARRAY_SIZE(fds) - 1, buf, len);
                    }
                }
            }
        }
    }
}


