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
#ifndef WSBRD_NS3_HPP
#define WSBRD_NS3_HPP

#include <ns3/callback.h>

/*
 * Declare symbols extern "C" so their names are not
 * mangled when loading libwsbrd-ns3 using dlsym.
 */
extern "C" {

/*
 * Simulation ID, should be different for each instance of libwsbrd-ns3.
 * It must correspond to an ns-3 context (or node ID), which will be used
 * to schedule events.
 */
extern int g_simulation_id;

/*
 * Callback called instead of write() when wsbrd sends data to the RCP.
 * The signature is: int uart_cb(const void *data, size_t size);
 */
extern ns3::Callback<int, const void *, size_t> g_uart_cb;

/*
 * File descriptor used when polling and reading data from the RCP, a pipe
 * read end can be specified for example.
 */
extern int g_uart_fd;

/*
 * Launch wsbrd with the specified config file.
 * This function does not return and should be launched in a thread.
 */
void wsbr_ns3_main(const char *config_filename);

} // extern "C"

#endif
