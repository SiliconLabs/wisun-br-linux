#ifndef WSBR_PCAPNG_H
#define WSBR_PCAPNG_H

typedef struct mcps_data_ie_list mcps_data_ie_list_t;
typedef struct mcps_data_ind mcps_data_ind_t;

void wsbr_pcapng_init(struct wsbr_ctxt *ctxt);
void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, mcps_data_ind_t *ind, mcps_data_ie_list_t *ie);

#endif
