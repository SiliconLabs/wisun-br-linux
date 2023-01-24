/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include <exception>
#include <limits.h>
#include <string.h>

#include <ns3/abort.h>

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
    char *argv[6];

    BUG_ON(g_uart_cb.IsNull());
    BUG_ON(g_uart_fd < 0);

    // Copy arguments to make sure they won't be modified outside of this function
    strcpy(config_arg, config_filename);

    // Cast to non-const, wsbrd is trusted to not modify its arguments
    argv[0] = (char *)"wsbrd";
    argv[1] = (char *)"-F";
    argv[2] = config_arg;
    argv[3] = (char *)"-u/dev/null"; // Provide a UART devive so parse_commandline succeeds
    argv[4] = (char *)"-D";
    argv[5] = NULL;

    wsbr_main(ARRAY_SIZE(argv) - 1, argv); // Does not return
}

// exit() is not thread-safe, so aborting is preferred.
extern "C" void __wrap_exit(int status)
{
    NS_ABORT_MSG("wsbrd exited");
}
