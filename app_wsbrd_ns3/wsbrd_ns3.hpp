#ifndef WSBRD_NS3_HPP
#define WSBRD_NS3_HPP

/*
 * Declare functions extern "C" so their names are not
 * mangled when loading libwsbrd-ns3 using dlsym.
 */
extern "C" {

/*
 * Launch wsbrd with the specified config file.
 * This function does not return and should be launched in a thread.
 */
void wsbr_ns3_main(const char *config_filename);

} // extern "C"

#endif
