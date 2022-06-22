#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

uint16_t crc16(const uint8_t *data, int len);
bool crc_check(const uint8_t *data, int len, uint16_t expected_crc);

#endif
