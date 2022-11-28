#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>
#include "int24.h"

uint16_t read_be16(const uint8_t ptr[2]);
uint16_t read_le16(const uint8_t ptr[2]);
uint24_t read_be24(const uint8_t ptr[3]);
uint24_t read_le24(const uint8_t ptr[3]);
uint32_t read_be32(const uint8_t ptr[4]);
uint32_t read_le32(const uint8_t ptr[4]);
uint64_t read_be64(const uint8_t ptr[8]);
uint64_t read_le64(const uint8_t ptr[8]);

uint8_t *write_be16(uint8_t ptr[2], uint16_t val);
uint8_t *write_le16(uint8_t ptr[2], uint16_t val);
uint8_t *write_be24(uint8_t ptr[3], uint24_t val);
uint8_t *write_le24(uint8_t ptr[3], uint24_t val);
uint8_t *write_be32(uint8_t ptr[4], uint32_t val);
uint8_t *write_le32(uint8_t ptr[4], uint32_t val);
uint8_t *write_be64(uint8_t ptr[8], uint64_t val);
uint8_t *write_le64(uint8_t ptr[8], uint64_t val);

#endif
