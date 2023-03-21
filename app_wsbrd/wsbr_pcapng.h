#ifndef WSBR_PCAPNG_H
#define WSBR_PCAPNG_H

struct wsbr_ctxt;
struct mcps_data_ind;
struct mcps_data_ie_list;

void wsbr_pcapng_init(struct wsbr_ctxt *ctxt);
void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, struct mcps_data_ind *ind, struct mcps_data_ie_list *ie);

#endif
