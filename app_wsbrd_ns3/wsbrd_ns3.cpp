#include <limits.h>
#include <string.h>

extern "C" {
#include "app_wsbrd/libwsbrd.h"
#include "common/utils.h"
}
#include "wsbrd_ns3.hpp"

void wsbr_ns3_main(const char *config_filename)
{
    char config_arg[PATH_MAX];
    char *argv[4];

    // Copy arguments to make sure they won't be modified outside of this function
    strcpy(config_arg, config_filename);

    // Cast to non-const, wsbrd is trusted to not modify its arguments
    argv[0] = (char *)"wsbrd";
    argv[1] = (char *)"-F";
    argv[2] = config_arg;
    argv[3] = NULL;

    wsbr_main(ARRAY_SIZE(argv) - 1, argv); // Does not return
}
