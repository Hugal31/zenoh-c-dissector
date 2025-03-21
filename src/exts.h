#pragma once

#include <epan/packet.h>

typedef void(*ext_dissector_t)(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, int length, void *data);
struct ext_dissector_table_entry {
  uint8_t id;
  ext_dissector_t dissector;
};
typedef struct ext_dissector_table_entry *ext_dissector_table_t;

int dissect_exts(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, ext_dissector_table_t dissector_table, void *data);
void dissect_qos_ext(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, int length, void *data);
void dissect_qos_type(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset, int length, void *data);

extern struct ext_dissector_table_entry default_ext_dissector_table[2];
