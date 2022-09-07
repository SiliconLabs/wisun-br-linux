#ifndef FUZZ_INTERFACES_H
#define FUZZ_INTERFACES_H

#define IF_SOCKET_COUNT 4

struct fuzz_ctxt;

enum {
    IF_TUN,
    IF_DHCP_SERVER,
    IF_EAPOL_RELAY,
    IF_BR_EAPOL_RELAY,
    IF_PAE_AUTH,
};

void fuzz_replay_socket_init(struct fuzz_ctxt *ctxt);

#endif
