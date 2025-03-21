#pragma once

#include <epan/packet.h>

#define MAX_ZID_SIZE 16

uint64_t read_zint(tvbuff_t *tvb, int *offset);
int dissect_zint(tvbuff_t *tvb, proto_tree *tree, int offset, int hfindex, proto_item **item, uint64_t *value);
/// @pre if @p dest is not null, it must have at least @p length * 2 + 1 free bytes
int dissect_zid(tvbuff_t *tvb, proto_tree *tree, int hfindex, int offset, int length, char *dest);
