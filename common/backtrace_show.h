/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef BACKTRACE_SHOW_H
#define BACKTRACE_SHOW_H

/*
 * backtrace_show() smartly decodes the backtrace and displays it. Thanks to
 * backtrace.h, the .eh_frames binary section is used to decode the stack
 * frames. Then:
 *   - if the debug symbols are available (ie. compiled with -g),
 *     backtrace_show() will resolve the symbol names, the filenames and the
 *     line numbers.
 *   - if the binary is not stripped, backtrace_show() will only resolve the
 *     symbol names.
 *   - if the binary is a shared library or if the binary is compiled with
 *     -rdynamic, backtrace_show() will resolve the names of the exported
 *     symbols only (static functions won't be available)
 *
 * This function is usually called from assert handler but it can be called from
 * any part of the code without disturbing the application. It can be useful
 * during debug.
 */

#ifdef HAVE_BACKTRACE

void backtrace_show();

#else

static inline void backtrace_show() { }

#endif

#endif
