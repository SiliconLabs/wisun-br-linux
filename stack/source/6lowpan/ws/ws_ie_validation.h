#ifndef WS_IE_VALIDATION_H
#define WS_IE_VALIDATION_H

#include <stdint.h>

struct ws_wp_netname;
struct ws_lcp_ie;
struct ws_us_ie;
struct ws_bs_ie;
struct ws_info;

bool ws_ie_validate_us(const struct ws_info *ws_info, const struct ws_us_ie *ie_us);
bool ws_ie_validate_bs(const struct ws_info *ws_info, const struct ws_bs_ie *ie_us);
bool ws_ie_validate_lcp(const struct ws_info *ws_info, const struct ws_lcp_ie *ie_lcp);
bool ws_ie_validate_netname(const struct ws_info *ws_info, const struct ws_wp_netname *ie_netname);

#endif
