#include <epan/packet.h>

#include "exts.h"
#include "fields.h"
#include "utils.h"

static ext_dissector_t try_get_dissector(ext_dissector_table_t dissector_table, uint8_t id) {
  while (dissector_table->id != 0 && dissector_table->id != id) {
    ++dissector_table;
  }
  return dissector_table->dissector;
}

static int dissect_ext(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, ext_dissector_table_t dissector_table, bool *has_more) {
  const uint8_t header = tvb_get_uint8(tvb, offset);
  const uint8_t id = header & 0xF;
  // const uint8_t mandatory = header & 0x10;
  const uint8_t enc = (header >> 5) & 0b11;
  *has_more = (header & 0x80) != 0;

  offset += 1;
  int start = offset;

  switch (enc) {
  default:
  case 0b00:
    start = offset - 1;
    break;
  case 0b01: {
    read_zint(tvb, &offset);
    break;
  }
  case 0b10: {
    const int length = (int)read_zint(tvb, &offset);
    start = offset;
    offset += length;
    break;
  }
  }
  const int length = offset - start;

  ext_dissector_t ext_dissector = dissector_table ? try_get_dissector(dissector_table, id) : NULL;
  if (ext_dissector) {
    ext_dissector(tvb, pinfo, tree, start, length);
  } else {
    if (enc == 0) {
      proto_item_prepend_text(proto_tree_add_item(tree, hf_ext_unit, tvb, start, length, ENC_NA),
        "Ext (%u", id);
    } else if (enc == 1) {
      proto_item *item;
      dissect_zint(tvb, tree, start, hf_ext_z64, &item, NULL);
      proto_item_prepend_text(item, "Ext (%u", id);
    } else {
      proto_item *item = proto_tree_add_item(tree, hf_ext_zbuf, tvb, start, length, ENC_NA);
      proto_item_prepend_text(item, "Ext (%u", id);
    }
  }

  return offset;
}

int dissect_exts(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, ext_dissector_table_t dissector_table) {
  bool has_more = true;
  while (has_more) {
    offset = dissect_ext(tvb, pinfo, tree, offset, dissector_table, &has_more);
  }
  return offset;
}
