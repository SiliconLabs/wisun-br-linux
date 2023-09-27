#ifndef WSBR_PCAPNG_H
#define WSBR_PCAPNG_H

struct wsbr_ctxt;
struct mcps_data_ind;
struct mcps_data_ie_list;

struct rcp;
struct arm_15_4_mac_parameters;
struct mcps_data_req;
struct mcps_data_req_ie_list;

void wsbr_pcapng_init(struct wsbr_ctxt *ctxt);
void wsbr_pcapng_write_ind_frame(struct wsbr_ctxt *ctxt, struct mcps_data_ind *ind, struct mcps_data_ie_list *ie);
void wsbr_pcapng_write_req_frame(struct wsbr_ctxt *ctxt,
                                 const struct rcp *rcp,
                                 const struct arm_15_4_mac_parameters *mac,
                                 const struct mcps_data_req *req,
                                 const struct mcps_data_req_ie_list *ie);

#endif
