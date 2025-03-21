cmake_minimum_required(VERSION 3.16)
project(LCDissectors LANGUAGES C)

find_package(Wireshark REQUIRED)

add_library(zenoh MODULE
    src/packet-zenoh.c
    src/conv.c
    src/conv.h
    src/exts.c
    src/exts.h
    src/fields.h
    src/key_exprs.c
    src/key_exprs.h
    src/utils.c
    src/utils.h)
target_link_libraries(zenoh PRIVATE epan)
set_target_properties(zenoh
    PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)
