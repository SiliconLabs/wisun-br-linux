cmake_minimum_required(VERSION  3.16.3)
project(wisun-host)

ADD_LIBRARY(wisun-host STATIC
    nanostack/source/BorderRouter/border_router.c
)
TARGET_INCLUDE_DIRECTORIES(wisun-host PRIVATE
    mbed-trace/
    mbed-client-libservice/mbed-client-libservice/
    nanostack-event-loop/nanostack-event-loop/
    nanostack/nanostack/
    nanostack/source/
)
