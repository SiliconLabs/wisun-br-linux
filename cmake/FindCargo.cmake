#
# SPDX-License-Identifier: LicenseRef-MSLA
# Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
#
# The licensor of this software is Silicon Laboratories Inc. Your use of this
# software is governed by the terms of the Silicon Labs Master Software License
# Agreement (MSLA) available at [1].  This software is distributed to you in
# Object Code format and/or Source Code format and is governed by the sections
# of the MSLA applicable to Object Code, Source Code and Modified Open Source
# Code. By using this software, you agree to the terms of the MSLA.
#
# [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
#
include(FindPackageHandleStandardArgs)
find_program(CARGO_COMMAND cargo)
mark_as_advanced(CARGO_COMMAND)

if (CARGO_COMMAND)
    execute_process(COMMAND ${CARGO_COMMAND} --version
                    OUTPUT_VARIABLE CARGO_VERSION_OUTPUT)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+"
           CARGO_VERSION "${CARGO_VERSION_OUTPUT}")
endif()

find_package_handle_standard_args(Cargo
    REQUIRED_VARS CARGO_COMMAND
    VERSION_VAR CARGO_VERSION
)
