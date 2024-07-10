/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/capability.h>
#include "common/log.h"

#include "commandline.h"

void drop_privileges(struct wsbrd_conf *conf)
{
    int ret;
    struct passwd *user;
    struct group *group;
    cap_t cap_p;
    cap_value_t cap_value = CAP_NET_ADMIN;

    group = getgrnam(conf->group);
    FATAL_ON(!group, 1, "group '%s' does not exist", conf->group);
    ret = cap_setgroups(group->gr_gid, 1, &group->gr_gid);
    FATAL_ON(ret, 2, "cap_setgroups: %m");

    user = getpwnam(conf->user);
    FATAL_ON(!user, 1, "user '%s' does not exist", conf->user);
    ret = cap_setuid(user->pw_uid);
    FATAL_ON(ret, 2, "cap_setuid: %m"); // cap_setuid to unprivileged user drops the effective flag on all capabilities

    cap_p = cap_get_proc();
    FATAL_ON(!cap_p, 2, "cap_get_proc: %m");
    ret = cap_clear_flag(cap_p, CAP_PERMITTED);
    FATAL_ON(ret, 2, "cap_clear_flag: %m");
    if (strlen(conf->neighbor_proxy)) {
        ret = cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_value, CAP_SET);
        FATAL_ON(ret, 2, "cap_set_flag: %m");
        ret = cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap_value, CAP_SET);
        FATAL_ON(ret, 2, "cap_set_flag: %m");
    }
    ret = cap_set_proc(cap_p);
    FATAL_ON(ret, 2, "cap_set_proc: %m");
    ret = cap_free(cap_p);
    FATAL_ON(ret, 2, "cap_free: %m");
}
