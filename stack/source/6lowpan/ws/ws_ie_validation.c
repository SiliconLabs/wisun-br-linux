#include "stack/source/6lowpan/ws/ws_bootstrap.h"
#include "stack/source/6lowpan/ws/ws_common.h"
#include "stack/source/6lowpan/ws/ws_ie_lib.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/mac/fhss_config.h"
#include "common/log.h"

#include "ws_ie_validation.h"

static bool ws_ie_validate_schedule(const struct ws_info *ws_info,
                                    const struct ws_generic_channel_info *chan_info,
                                    const char *ie_str)
{
    if (!ws_chan_plan_validate(chan_info, &ws_info->hopping_schedule)) {
        TRACE(TR_DROP, "drop 15.4     : %s channel plan mismatch", ie_str);
        return false;
    }

    if (!ws_chan_func_validate(chan_info->channel_function)) {
        TRACE(TR_DROP, "drop 15.4     : %s channel function unsupported", ie_str);
        return false;
    }

    switch (chan_info->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
    case WS_EXC_CHAN_CTRL_RANGE:
    case WS_EXC_CHAN_CTRL_BITMASK:
        break;
    default:
        TRACE(TR_DROP, "drop 15.4     : %s excluded channel control unsupported", ie_str);
        return false;
    }

    return true;
}

bool ws_ie_validate_us(const struct ws_info *ws_info, const struct ws_us_ie *ie_us)
{
    return ws_ie_validate_schedule(ws_info, &ie_us->chan_plan, "US-IE");
}

bool ws_ie_validate_bs(const struct ws_info *ws_info, const struct ws_bs_ie *ie_bs)
{
    return ws_ie_validate_schedule(ws_info, &ie_bs->chan_plan, "BS-IE");
}

bool ws_ie_validate_lcp(const struct ws_info *ws_info, const struct ws_lcp_ie *ie_lcp)
{
    if (ie_lcp->chan_plan.channel_plan != 2) {
        TRACE(TR_DROP, "drop 15.4     : LCP-IE channel plan invalid");
        return false;
    }
    return ws_ie_validate_schedule(ws_info, &ie_lcp->chan_plan, "LCP-IE");
}
