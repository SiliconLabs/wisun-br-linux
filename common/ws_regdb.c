/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "ws_regdb.h"

const struct phy_params phy_params_table[] = {
    /* ,- rail_phy_mode_id
       |   ,- phy_mode_id  ,- datarate             ofdm_mcs -.  ,- ofdm_option
       |   | modulation    |   mode  fsk_modulation_index    |  |   fec  */
    {  1,  1, M_2FSK,   50000, 0x1a, MODULATION_INDEX_0_5,   0, 0, false },
    {  2,  2, M_2FSK,   50000, 0x1b, MODULATION_INDEX_1_0,   0, 0, false },
    {  3,  3, M_2FSK,  100000, 0x2a, MODULATION_INDEX_0_5,   0, 0, false },
    {  4,  4, M_2FSK,  100000, 0x2b, MODULATION_INDEX_1_0,   0, 0, false },
    {  5,  5, M_2FSK,  150000, 0x03, MODULATION_INDEX_0_5,   0, 0, false },
    {  6,  6, M_2FSK,  200000, 0x4a, MODULATION_INDEX_0_5,   0, 0, false },
    {  7,  7, M_2FSK,  200000, 0x4b, MODULATION_INDEX_1_0,   0, 0, false },
    {  8,  8, M_2FSK,  300000, 0x05, MODULATION_INDEX_0_5,   0, 0, false },
    { 17, 17, M_2FSK,   50000, 0x91, MODULATION_INDEX_0_5,   0, 0,  true },
    { 18, 18, M_2FSK,   50000, 0x92, MODULATION_INDEX_1_0,   0, 0,  true },
    { 19, 19, M_2FSK,  100000, 0x93, MODULATION_INDEX_0_5,   0, 0,  true },
    { 20, 20, M_2FSK,  100000, 0x94, MODULATION_INDEX_1_0,   0, 0,  true },
    { 21, 21, M_2FSK,  150000, 0x95, MODULATION_INDEX_0_5,   0, 0,  true },
    { 22, 22, M_2FSK,  200000, 0x96, MODULATION_INDEX_0_5,   0, 0,  true },
    { 23, 23, M_2FSK,  200000, 0x97, MODULATION_INDEX_1_0,   0, 0,  true },
    { 24, 24, M_2FSK,  300000, 0x98, MODULATION_INDEX_0_5,   0, 0,  true },
    { 32, 34, M_OFDM,  400000, 0xa2, MODULATION_INDEX_UNDEF, 2, 1, false },
    { 32, 35, M_OFDM,  800000, 0xa3, MODULATION_INDEX_UNDEF, 3, 1, false },
    { 32, 36, M_OFDM, 1200000, 0xa4, MODULATION_INDEX_UNDEF, 4, 1, false },
    { 32, 37, M_OFDM, 1600000, 0xa5, MODULATION_INDEX_UNDEF, 5, 1, false },
    { 32, 38, M_OFDM, 2400000, 0xa6, MODULATION_INDEX_UNDEF, 6, 1, false },
    { 48, 51, M_OFDM,  400000, 0xb3, MODULATION_INDEX_UNDEF, 3, 2, false },
    { 48, 52, M_OFDM,  600000, 0xb4, MODULATION_INDEX_UNDEF, 4, 2, false },
    { 48, 53, M_OFDM,  800000, 0xb5, MODULATION_INDEX_UNDEF, 5, 2, false },
    { 48, 54, M_OFDM, 1200000, 0xb6, MODULATION_INDEX_UNDEF, 6, 2, false },
    { 64, 68, M_OFDM,  300000, 0xc4, MODULATION_INDEX_UNDEF, 4, 3, false },
    { 64, 69, M_OFDM,  400000, 0xc5, MODULATION_INDEX_UNDEF, 5, 3, false },
    { 64, 70, M_OFDM,  600000, 0xc6, MODULATION_INDEX_UNDEF, 6, 3, false },
    { 80, 84, M_OFDM,  150000, 0xd4, MODULATION_INDEX_UNDEF, 4, 4, false },
    { 80, 85, M_OFDM,  200000, 0xd5, MODULATION_INDEX_UNDEF, 5, 4, false },
    { 80, 86, M_OFDM,  300000, 0xd6, MODULATION_INDEX_UNDEF, 6, 4, false },
    {  0,  0, M_UNDEFINED,  0,    0, MODULATION_INDEX_UNDEF, 0, 0, false },
};

const struct chan_params chan_params_table[] = {
    /*                                                    chan_count -.
                               chan_plan_id -.    chan_spacing -.     |    ,- chan_count_valid
         domain    class   regional_reg      |   chan0_freq     |     |    |      valid_phy_modes */
    { REG_DOMAIN_AZ, 1, REG_REGIONAL_NONE,   0,  915200000,  200000,  64,  64, {  2,  3,                     }, }, // REG_DOMAIN_AZ and REG_DOMAIN_NZ share the same ID
    { REG_DOMAIN_AZ, 2, REG_REGIONAL_NONE,   0,  915400000,  400000,  32,  32, {  5,  6,  8,                 }, },
    { REG_DOMAIN_BZ, 1, REG_REGIONAL_NONE,   1,  902200000,  200000, 129,  90, {  2,  3, 18, 19, 84, 85, 86, }, .chan_allowed = "0-25,65-255", },
    { REG_DOMAIN_BZ, 2, REG_REGIONAL_NONE,   2,  902400000,  400000,  64,  43, {  5,  6, 21, 22, 68, 69, 70, }, .chan_allowed = "0-11,33-255", },
    { REG_DOMAIN_BZ, 3, REG_REGIONAL_NONE,   3,  902600000,  600000,  42,  28, {  8, 24,                     }, .chan_allowed = "0-7,22-255", },
    { REG_DOMAIN_BZ, 0, REG_REGIONAL_NONE,   4,  902800000,  800000,  32,  22, { 51, 52, 53, 54,             }, .chan_allowed = "0-5,16-255", },
    { REG_DOMAIN_BZ, 0, REG_REGIONAL_NONE,   5,  903200000, 1200000,  21,  13, { 34, 35, 36, 37, 38,         }, .chan_allowed = "0-2,11-255", },
    { REG_DOMAIN_CN, 1, REG_REGIONAL_NONE,   0,  470200000,  200000, 199, 199, {  2,  3,  5,                 }, },
    { REG_DOMAIN_CN, 2, REG_REGIONAL_NONE,   0,  779200000,  200000,  39,  39, {  2,  3,                     }, },
    { REG_DOMAIN_CN, 3, REG_REGIONAL_NONE,   0,  779400000,  400000,  19,  19, {  5,  6,  8,                 }, },
    { REG_DOMAIN_CN, 4, REG_REGIONAL_NONE,   0,  920625000,  250000,  16,  16, {  2,  3,  5,                 }, },
    { REG_DOMAIN_EU, 1, REG_REGIONAL_NONE,   0,  863100000,  100000,  69,  69, {  1,                         }, },
    { REG_DOMAIN_EU, 2, REG_REGIONAL_NONE,   0,  863100000,  200000,  35,  35, {  3,  5,                     }, },
    // Except the mask, same than class 1
    { REG_DOMAIN_EU, 0, REG_REGIONAL_NONE,  32,  863100000,  100000,  69,  62, {  1, 17,                     }, .chan_allowed = "0-54,57-60,64,67-255", },
    // Except the mask, same than class 2
    { REG_DOMAIN_EU, 0, REG_REGIONAL_NONE,  33,  863100000,  200000,  35,  29, {  3,  5, 19, 21, 84, 85, 86, }, .chan_allowed = "0-26,29,34-255", },
    { REG_DOMAIN_EU, 3, REG_REGIONAL_NONE,  34,  870100000,  100000,  55,  55, {  1, 17,                     }, },
    { REG_DOMAIN_EU, 4, REG_REGIONAL_NONE,  35,  870200000,  200000,  27,  27, {  3,  5, 19, 21, 84, 85, 86, }, },
    { REG_DOMAIN_EU, 0, REG_REGIONAL_NONE,  36,  863100000,  100000, 125, 118, {  1, 17,                     }, .chan_allowed = "0-54,57-60,64,67-255", },
    { REG_DOMAIN_EU, 0, REG_REGIONAL_NONE,  37,  863100000,  200000,  62,  56, {  3,  5, 19, 21, 84, 85, 86, }, .chan_allowed = "0-26,29,34-255", },
    { REG_DOMAIN_HK, 1, REG_REGIONAL_NONE,   0,  920200000,  200000,  24,  24, {  2,  3,                     }, },
    { REG_DOMAIN_HK, 2, REG_REGIONAL_NONE,   0,  920400000,  400000,  12,  12, {  5,  6,  8,                 }, },
    { REG_DOMAIN_IN, 1, REG_REGIONAL_NONE,   0,  865100000,  100000,  19,  19, {  1,                         }, },
    { REG_DOMAIN_IN, 2, REG_REGIONAL_NONE,   0,  865100000,  200000,  10,  10, {  3,  5,                     }, },
    { REG_DOMAIN_JP, 1, REG_REGIONAL_ARIB,   0,  920600000,  200000,  38,  38, {  2,                         }, .chan_allowed = "9-255", },
    { REG_DOMAIN_JP, 2, REG_REGIONAL_ARIB,   0,  920900000,  400000,  18,  18, {  4,  5,                     }, .chan_allowed = "4-255", },
    { REG_DOMAIN_JP, 3, REG_REGIONAL_ARIB,   0,  920800000,  600000,  12,  12, {  7,  8,                     }, .chan_allowed = "3-255", },
    { REG_DOMAIN_JP, 1, REG_REGIONAL_ARIB,  21,  920928200,  400000,  38,  29, {  2, 18, 84, 85, 86,         }, .chan_allowed = "9-255", },
    { REG_DOMAIN_JP, 2, REG_REGIONAL_ARIB,  22,  920928400,  400000,  18,  14, {  4,  5, 20, 21, 68, 69, 70, }, .chan_allowed = "4-255", },
    { REG_DOMAIN_JP, 3, REG_REGIONAL_ARIB,  23,  920928600,  400000,  12,   9, {  7,  8, 23, 24,             }, .chan_allowed = "3-255", },
    { REG_DOMAIN_JP, 0, REG_REGIONAL_ARIB,  24,  920928800,  400000,   9,   7, { 51, 52, 53, 54,             }, .chan_allowed = "2-255", },
    { REG_DOMAIN_KR, 1, REG_REGIONAL_NONE,   0,  917100000,  200000,  32,  32, {  2,  3,                     }, },
    { REG_DOMAIN_KR, 2, REG_REGIONAL_NONE,   0,  917300000,  400000,  16,  16, {  5,  6,  8,                 }, },
    { REG_DOMAIN_MX, 1, REG_REGIONAL_NONE,   0,  902200000,  200000, 129, 129, {  2,  3,                     }, },
    { REG_DOMAIN_MX, 2, REG_REGIONAL_NONE,   0,  902400000,  400000,  64,  64, {  5,  6,  8,                 }, },
    { REG_DOMAIN_MY, 1, REG_REGIONAL_NONE,   0,  919200000,  200000,  19,  19, {  2,  3,                     }, },
    { REG_DOMAIN_MY, 2, REG_REGIONAL_NONE,   0,  919400000,  400000,  10,  10, {  5,  6,  8,                 }, },
    { REG_DOMAIN_NA, 1, REG_REGIONAL_NONE,   1,  902200000,  200000, 129, 129, {  2,  3, 18, 19, 84, 85, 86, }, },
    { REG_DOMAIN_NA, 2, REG_REGIONAL_NONE,   2,  902400000,  400000,  64,  64, {  5,  6, 21, 22, 68, 69, 70, }, },
    { REG_DOMAIN_NA, 3, REG_REGIONAL_NONE,   3,  902600000,  600000,  42,  42, {  8, 24,                     }, },
    { REG_DOMAIN_NA, 0, REG_REGIONAL_NONE,   4,  902800000,  800000,  32,  32, { 51, 52, 53, 54,             }, },
    { REG_DOMAIN_NA, 0, REG_REGIONAL_NONE,   5,  903200000, 1200000,  21,  21, { 34, 35, 36, 37, 38,         }, },
    { REG_DOMAIN_PH, 1, REG_REGIONAL_NONE,   0,  915200000,  200000,  14,  14, {  2,  3,                     }, },
    { REG_DOMAIN_PH, 2, REG_REGIONAL_NONE,   0,  915400000,  400000,   7,   7, {  5,  6,  8,                 }, },
    { REG_DOMAIN_SG, 1, REG_REGIONAL_NONE,   0,  866100000,  100000,  29,  29, {  1,                         }, },
    { REG_DOMAIN_SG, 2, REG_REGIONAL_NONE,   0,  866100000,  200000,  15,  15, {  3,  5,                     }, },
    { REG_DOMAIN_SG, 3, REG_REGIONAL_NONE,   0,  866300000,  400000,   7,   7, {  6,  8,                     }, },
    { REG_DOMAIN_SG, 4, REG_REGIONAL_NONE,   0,  920200000,  200000,  24,  24, {  2,  3,                     }, },
    { REG_DOMAIN_SG, 5, REG_REGIONAL_NONE,   0,  920400000,  400000,  12,  12, {  5,  6,  8,                 }, },
    { REG_DOMAIN_TH, 1, REG_REGIONAL_NONE,   0,  920200000,  200000,  24,  24, {  2,  3,                     }, },
    { REG_DOMAIN_TH, 2, REG_REGIONAL_NONE,   0,  920400000,  400000,  12,  12, {  5,  6,  8,                 }, },
    { REG_DOMAIN_VN, 1, REG_REGIONAL_NONE,   0,  920200000,  200000,  24,  24, {  2,  3,                     }, },
    { REG_DOMAIN_VN, 2, REG_REGIONAL_NONE,   0,  920400000,  400000,  12,  12, {  5,  6,  8,                 }, },
    { REG_DOMAIN_WW, 1, REG_REGIONAL_NONE,   0, 2400200000,  200000, 416, 416, {  2,  3,                     }, },
    { REG_DOMAIN_WW, 2, REG_REGIONAL_NONE,   0, 2400400000,  400000, 207, 207, {  5,  6,  8,                 }, },
    { REG_DOMAIN_UNDEF, 0, REG_REGIONAL_NONE, 0,         0,       0,   0,   0, {                             }, },
};
