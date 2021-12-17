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
};

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "broadcast server to create networks of wshwsim\n");
    exit(exit_code);
}

void parse_commandline(struct ctxt *ctxt, int argc, char *argv[])
{
    const char *opts_short = "h";
    static const struct option opts_long[] = {
        { "help",  no_argument,       0,  'h' },
        { 0,       0,                 0,   0  }
    };
    int opt;

    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
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


