#!/bin/echo run with: docker build . -f
# SPDX-License-Identifier: LicenseRef-MSLA
# SPDX-Copyright-Text: (c) 2024 Silicon Laboratories Inc. (www.silabs.com)

FROM debian:12

RUN echo "# log: Setup system"  \
  && set -x \
  && apt-get update -y \
  && apt-get install -y sudo make \
  && date -u

ENV project wisun-br-linux
ENV workdir /usr/local/src/${project}
WORKDIR ${workdir}
COPY helper.mk ${workdir}
RUN echo "# log: Setup ${project}" \
  && set -x  \
  && ./helper.mk setup \
  && date -u

COPY . ${workdir}
WORKDIR ${workdir}
RUN echo "# log: Build ${project}" \
  && set -x  \
  && ./helper.mk prepare build \
  && date -u
