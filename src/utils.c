#include <epan/packet.h>

#include "utils.h"

#define VLE_LEN_MAX 9
uint64_t read_zint(tvbuff_t *tvb, int *offset)
{
  uint8_t b = tvb_get_uint8(tvb, *offset);
  uint64_t v = 0;
  size_t i = 0;
  while ((b & 0x80) != 0 && i != (7 * (VLE_LEN_MAX - 1))) {
    v |= (uint64_t)(b & 0x7F) << i;
    i += 7;
    *offset = *offset + 1;
    b = tvb_get_uint8(tvb, *offset);
  }
  *offset = *offset + 1;
  v |= (uint64_t)b << i;
  return v;
}

int dissect_zint(tvbuff_t *tvb, proto_tree *tree, int offset,
                        int hfindex, proto_item **item, uint64_t *value) {
  const int start = offset;
  uint64_t ret = read_zint(tvb, &offset);
  const int length = offset - start;
  proto_item *tree_item = proto_tree_add_uint64(
      tree, hfindex, tvb, start, length, ret);

  if (value)
    *value = ret;
  if (item)
    *item = tree_item;
  return offset;
}
