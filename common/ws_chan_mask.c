#include <errno.h>

#include "common/bits.h"

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
