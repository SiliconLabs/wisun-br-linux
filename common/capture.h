/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef CAPTURE_H
#define CAPTURE_H

#include <sys/socket.h>
#include <stdint.h>

/*
 * Event capture module. Stores HIF packets to a raw binary file, and inserts
 * special commands to record timer ticks and external network events such as
 * socket reads.
 * 
 * The timerfd used to handle system timing must be registered using
 * capture_register_timerfd(). Networking file descriptors such as TUN device
 * and sockets must be registered using capture_register_netfd(). Regular HIF
 * frames received by the RCP must be recorded by calling capture_record_hif().
 * File descriptor interactions must use the xread()/xwrite() variants, which
 * call the regular read()/write() and write data to the capture file only
 * after capture_start() is called to set the output file. Finally, all random
 * number generation must use xgetrandom() to ensure reproducibility.
 */

ssize_t xread(int fd, void *buf, size_t buf_len);
ssize_t xrecv(int fd, void *buf, size_t buf_len, int flags);
ssize_t xrecvfrom(int fd, void *buf, size_t buf_len, int flag,
                  struct sockaddr *src, socklen_t *src_len);
ssize_t xrecvmsg(int fd, struct msghdr *msg, int flags);

ssize_t xwrite(int fd, const void *buf, size_t buf_len);
ssize_t xsend(int fd, const void *buf, size_t buf_len, int flags);
ssize_t xsendto(int fd, const void *buf, size_t buf_len, int flags,
                const struct sockaddr *dst, socklen_t dst_len);
ssize_t xsendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t xgetrandom(void *buf, size_t buf_len, unsigned int flags);

void capture_register_timerfd(int fd);
void capture_register_netfd(int fd);
void capture_record_hif(const void *buf, size_t buf_len);
void capture_start(const char *filename);

#endif
