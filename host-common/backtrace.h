/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef BACKTRACE_H
#define BACKTRACE_H

#ifdef HAVE_BACKTRACE

void backtrace_show();

#else

static inline void backtrace_show() { }

#endif

#endif
