/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef BUS_SPI_H
#define BUS_SPI_H

#include <stdbool.h>
#include <stdint.h>

struct wsbr_ctxt;

int mux_gpio_open(const char *device, bool use_fall_edge);
int mux_spi_open(const char *device, uint32_t frequency, uint8_t mode);
int mux_spi_tx(struct wsbr_ctxt *ctxt, const void *buf, unsigned int len);
int mux_spi_rx(struct wsbr_ctxt *ctxt, void *buf, unsigned int len);

#endif

