#pragma once

#include <epan/packet.h>

int dissect_key_expr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     int offset, bool has_suffix, bool mapping,
                     const char **ret);