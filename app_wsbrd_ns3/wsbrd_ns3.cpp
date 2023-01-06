#include <limits.h>
#include <string.h>

extern "C" {
#include "app_wsbrd/libwsbrd.h"
#include "common/utils.h"
#include "common/log.h"
}
#include "wsbrd_ns3.hpp"

int g_simulation_id;

void wsbr_ns3_main(const char *config_filename)
{
    char config_arg[PATH_MAX];
    char *argv[5];

    BUG_ON(g_uart_cb.IsNull());
    BUG_ON(g_uart_fd < 0);

    // Copy arguments to make sure they won't be modified outside of this function
    strcpy(config_arg, config_filename);

    // Cast to non-const, wsbrd is trusted to not modify its arguments
    argv[0] = (char *)"wsbrd";
    argv[1] = (char *)"-F";
    argv[2] = config_arg;
    argv[3] = (char *)"-u/dev/null"; // Provide a UART devive so parse_commandline succeeds
    argv[4] = NULL;

    wsbr_main(ARRAY_SIZE(argv) - 1, argv); // Does not return
}
