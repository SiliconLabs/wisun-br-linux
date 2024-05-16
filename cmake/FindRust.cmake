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
find_program(RUST_COMMAND rustc)
mark_as_advanced(RUST_COMMAND)
mark_as_advanced(RUST_TARGET)

if (RUST_COMMAND)
    execute_process(COMMAND ${RUST_COMMAND} --version --verbose
                    OUTPUT_VARIABLE RUST_VERSION_OUTPUT)
    if(RUST_VERSION_OUTPUT MATCHES "rustc ([0-9]+\\.[0-9]+\\.[0-9]+)(-nightly)?")
        set(RUST_VERSION "${CMAKE_MATCH_1}")
    endif()
    if(RUST_VERSION_OUTPUT MATCHES "host: ([a-zA-Z0-9_\\-]*)")
        set(RUST_HOST "${CMAKE_MATCH_1}")
    endif()

    if (WIN32)
        set(_RUST_VENDOR "pc-windows")
        if (CMAKE_VS_PLATFORM_NAME)
            if (CMAKE_VS_PLATFORM_NAME STREQUAL "Win32")
                set(_RUST_ARCH i686)
            elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "x64")
                set(_RUST_ARCH x86_64)
            elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
                set(_RUST_ARCH aarch64)
            else()
                message(WARNING "VS Platform '${CMAKE_VS_PLATFORM_NAME}' not recognized")
            endif()
        else ()
            if (NOT DEFINED CMAKE_SIZEOF_VOID_P)
                message(FATAL_ERROR "Compiler hasn't been enabled yet - can't determine the target architecture")
            endif()

            if (CMAKE_SIZEOF_VOID_P EQUAL 8)
                set(_RUST_ARCH x86_64)
            else()
                set(_RUST_ARCH i686)
            endif()
        endif()

        if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            set(_RUST_ABI gnu)
        else()
            set(_RUST_ABI msvc)
        endif()

        set(_RUST_TARGET "${_RUST_ARCH}-${_RUST_VENDOR}-${_RUST_ABI}")
    elseif(ANDROID)
        if(CMAKE_ANDROID_ARCH_ABI STREQUAL armeabi-v7a)
            if(CMAKE_ANDROID_ARM_MODE)
                set(_RUST_TARGET armv7-linux-androideabi)
            else()
                set(_RUST_TARGET thumbv7neon-linux-androideabi)
            endif()
        elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL arm64-v8a)
            set(_RUST_TARGET aarch64-linux-android)
        elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL x86)
            set(_RUST_TARGET i686-linux-android)
        elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL x86_64)
            set(_RUST_TARGET x86_64-linux-android)
        endif()
    else()
        set(_RUST_TARGET ${RUST_HOST})
    endif()
    set(RUST_TARGET ${_RUST_TARGET} CACHE STRING "Rust target triple")
    message(STATUS "Rust Target: ${RUST_TARGET}")
endif()

find_package_handle_standard_args(Rust
    REQUIRED_VARS RUST_COMMAND RUST_TARGET
    VERSION_VAR RUST_VERSION
)
