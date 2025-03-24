cmake_minimum_required(VERSION 3.16)
project(LCDissectors LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LZ4 REQUIRED IMPORTED_TARGET liblz4)
find_package(Wireshark REQUIRED)

add_library(
  zenoh MODULE
  src/packet-zenoh.c
  src/conv.c
  src/conv.h
  src/exts.c
  src/exts.h
  src/fields.h
  src/key_exprs.c
  src/key_exprs.h
  src/lz4.c
  src/lz4.h
  src/utils.c
  src/utils.h)
target_link_libraries(zenoh PRIVATE epan PkgConfig::LZ4)
set_target_properties(zenoh PROPERTIES C_VISIBILITY_PRESET hidden
                                       VISIBILITY_INLINES_HIDDEN ON)
