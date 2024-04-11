#include <errno.h>

#include "common/bits.h"
#include "common/log.h"
#include "common/hif.h"
#include "common/parsers.h"
#include "common/ws_regdb.h"

#include "ws_chan_mask.h"

int ws_chan_mask_get_fixed(const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    int val = -EINVAL;

    for (int i = 0; i < 8 * WS_CHAN_MASK_LEN; i++) {
        if (bittest(chan_mask, i)) {
            if (val >= 0)
                return -EINVAL;
            val = i;
        }
    }
    return val;
}

void ws_chan_mask_calc_reg(uint8_t  chan_mask[WS_CHAN_MASK_LEN],
                           uint16_t chan_count,
                           uint8_t  regional_regulation,
                           uint8_t  regulatory_domain,
                           uint8_t  op_class,
                           uint8_t  chan_plan_id)
{
    const struct chan_params *chan_params;

    chan_params = ws_regdb_chan_params(regulatory_domain, chan_plan_id, op_class);
    WARN_ON(chan_params && chan_params->chan_count != chan_count);
    BUG_ON(chan_count >= 8 * WS_CHAN_MASK_LEN);

    memset(chan_mask, 0xFF, 32);
    if (chan_params && chan_params->chan_allowed)
        parse_bitmask(chan_mask, 32, chan_params->chan_allowed);
    if (regional_regulation == HIF_REG_ARIB) {
        // For now, ARIB is not supported for custom channel plans
        BUG_ON(!chan_params);
        // For now, ARIB is not supported outside of Japan
        BUG_ON(chan_params->reg_domain != REG_DOMAIN_JP);
        // Note: ChanPlanIds for JP already include these masks
        if (chan_params->op_class == 1)
            bitfill(chan_mask, false, 0, 8); // Allowed channels: "9-255"
        if (chan_params->op_class == 2)
            bitfill(chan_mask, false, 0, 3); // Allowed channels: "4-255"
        if (chan_params->op_class == 3)
            bitfill(chan_mask, false, 0, 2); // Allowed channels: "3-255"
    }
    bitfill(chan_mask, false, chan_count, 255);
}
