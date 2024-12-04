/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)

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
#include <sys/types.h>

extern "C" {
#include "tools/fuzz/rand.h"
}

#include <ns3/random-variable-stream.h>
#include <ns3/rng-seed-manager.h>
#include <ns3/sl-wisun-linux.hpp>

/*
 * When fuzz capture is enabled, the wsbrd-fuzz generator is used (libc).
 * Otherwise the ns-3 generator is used to enable seeding of the entire
 * simulation. Note that since the simulation of wsbrd is not deterministic
 * currently, using the ns-3 generator does not provide any advantages, but
 * this may change in the future.
 */
ssize_t fuzz_real_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    static bool init = false;
    static ns3::Ptr<ns3::UniformRandomVariable> rand_source =
        ns3::CreateObject<ns3::UniformRandomVariable>();

    if (!init) {
        rand_source->SetStream(ns3::RngSeedManager::GetSeed() + g_simulation_id);
        init = true;
    }

    for (size_t i = 0; i < buflen; i++)
        ((uint8_t *)buf)[i] = rand_source->GetInteger(0, 255);

    return buflen;
}
