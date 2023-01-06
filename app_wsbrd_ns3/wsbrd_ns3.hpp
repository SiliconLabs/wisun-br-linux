#ifndef WSBRD_NS3_HPP
#define WSBRD_NS3_HPP

#include <ns3/callback.h>

/*
 * Declare symbols extern "C" so their names are not
 * mangled when loading libwsbrd-ns3 using dlsym.
 */
extern "C" {

/*
 * Callback called instead of write() when wsbrd sends data to the RCP.
 * The signature is: int uart_cb(const void *data, size_t size);
 */
extern ns3::Callback<int, const void *, size_t> g_uart_cb;

/*
 * Launch wsbrd with the specified config file.
 * This function does not return and should be launched in a thread.
 */
void wsbr_ns3_main(const char *config_filename);

} // extern "C"

#endif
