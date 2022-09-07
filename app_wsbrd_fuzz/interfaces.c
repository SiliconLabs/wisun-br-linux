#include <stdint.h>
#include <unistd.h>

#include "nsconfig.h"
#include "stack/source/security/kmp/kmp_socket_if.h"
#include "stack/dhcp_service_api.h"
#include "stack/ws_bbr_api.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "common/log.h"
#include "common/spinel_buffer.h"
#include "interfaces.h"
#include "wsbrd_fuzz.h"
#include "capture.h"

static struct {
    int interface;
    int (*get_capture_fd)();
} s_sockets[] = {
    { IF_DHCP_SERVER,    dhcp_service_get_server_socket_fd     },
    { IF_EAPOL_RELAY,    ws_bbr_eapol_auth_relay_get_socket_fd },
    { IF_BR_EAPOL_RELAY, ws_bbr_eapol_relay_get_socket_fd      },
    { IF_PAE_AUTH,       kmp_socket_if_get_pae_socket_fd       },
};

void __wrap_wsbr_spinel_replay_interface(struct spinel_buffer *buf)
{
    uint8_t interface;
    uint8_t *data;
    size_t size;
    int ret;

    FATAL_ON(!(g_ctxt.rcp_init_state & RCP_INIT_DONE), 1, "interface command received during RCP init");
    FATAL_ON(!g_fuzz_ctxt.replay_count, 1, "interface command received while replay is disabled");

    interface = spinel_pop_u8(buf);
    if (buf->err)
        return;

    if (interface != IF_TUN)
        return;

    size = spinel_pop_data_ptr(buf, &data);
    ret = write(g_fuzz_ctxt.tun_pipe[1], data, size);
    FATAL_ON(ret < 0, 2, "write: %m");
    FATAL_ON(ret < size, 2, "write: Short write");
}

static void fuzz_capture_socket(int fd, void *buf, size_t size)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (size <= 0)
        return;

    for (int i = 0; i < ARRAY_SIZE(s_sockets); i++) {
        if (fd == s_sockets[i].get_capture_fd()) {
            fuzz_capture_timers(ctxt);
            fuzz_capture_interface(ctxt, s_sockets[i].interface, buf, size);
            return;
        }
    }
    BUG("invalid socket");
}

ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t size;

    size = __real_recv(sockfd, buf, len, flags);
    if (g_fuzz_ctxt.capture_enabled)
        fuzz_capture_socket(sockfd, buf, size);

    return size;
}

ssize_t __real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t size;

    size = __real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (g_fuzz_ctxt.capture_enabled)
        fuzz_capture_socket(sockfd, buf, size);

    return size;
}
