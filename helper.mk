#!/usr/bin/make -f
# -*- makefile -*-
# ex: set tabstop=4 noexpandtab:
# -*- coding: utf-8 -*
#
# SPDX-License-Identifier: LicenseRef-MSLA
# SPDX-Copyright-Text: (c) 2024 Silicon Laboratories Inc. (www.silabs.com)

tmpdir?=${CURDIR}/tmp

sudo?=sudo

export CMAKE_PREFIX_PATH=${tmpdir}/usr/local/cmake

debian_packages?=build-essential \
  git cmake sudo rustc pkg-config \
  libnl-route-3-dev libdbus-1-dev

mbedtls_url?=https://github.com/ARMmbed/mbedtls
mbedtls_rev?=v3.0.0


build:
	cmake .
	cmake --build .
	make install DESTDIR="${tmpdir}"

mbedtls:
	git clone --branch=${mbedtls_rev} --recursive --depth=1 ${mbedtls_url}

prepare: mbedtls
	cd $< \
	&& cmake . \
	&& cmake --build . \
	&& make install DESTDIR="${tmpdir}"

setup:
	${sudo} apt-get install -y ${debian_packages}

