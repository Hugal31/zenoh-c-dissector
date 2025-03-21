#pragma once

#include <epan/packet.h>

uint64_t read_zint(tvbuff_t *tvb, int *offset);
int dissect_zint(tvbuff_t *tvb, proto_tree *tree, int offset, int hfindex, proto_item **item, uint64_t *value);
