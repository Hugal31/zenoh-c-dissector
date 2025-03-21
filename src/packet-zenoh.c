#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

#include "conv.h"
#include "exts.h"
#include "fields.h"
#include "key_exprs.h"
#include "utils.h"

WS_DLL_PUBLIC_DEF char const *plugin_version = "0.1.0";
WS_DLL_PUBLIC_DEF int plugin_want_major = 4;
WS_DLL_PUBLIC_DEF int plugin_want_minor = 4;

int proto_zenoh;
static dissector_handle_t zenoh_handle;

#define MAX_ZID_SIZE 16

#define zh_transport_msg_type_names_VALUE_STRING_LIST(V) \
    V( ZENOH_TRANSPORT_OAM, 0, "OAM" ) \
  V( ZENOH_TRANSPORT_INIT, 1, "INIT" ) \
  V( ZENOH_TRANSPORT_OPEN, 2, "OPEN" ) \
  V( ZENOH_TRANSPORT_CLOSE, 3, "CLOSE" ) \
  V( ZENOH_TRANSPORT_KEEP_ALIVE, 4, "KEEP_ALIVE" ) \
  V( ZENOH_TRANSPORT_FRAME, 5, "FRAME" ) \
  V( ZENOH_TRANSPORT_FRAGMENT, 6, "FRAGMENT" ) \
  V( ZENOH_TRANSPORT_JOIN, 7, "JOIN" )

VALUE_STRING_ENUM(zh_transport_msg_type_names);
VALUE_STRING_ARRAY(zh_transport_msg_type_names);

#define zh_net_msg_type_names_VALUE_STRING_LIST(V)                             \
  V( ZENOH_NET_OAM, 0x1F, "OAM" )                                                \
  V( ZENOH_NET_DECLARE, 0x1E, "Declare" )                                        \
  V( ZENOH_NET_PUSH, 0x1D, "Push" )                                              \
  V( ZENOH_NET_REQUEST, 0x1C, "Request" )                                          \
  V( ZENOH_NET_RESPONSE, 0x1B, "Response" )                                    \
  V( ZENOH_NET_RESPONSE_FINAL, 0x1A, "ResponseFinal" )                                    \
  V( ZENOH_NET_INTEREST, 0x19, "Intereset" )

VALUE_STRING_ENUM(zh_net_msg_type_names);
VALUE_STRING_ARRAY(zh_net_msg_type_names);

#define zh_declare_type_names_VALUE_STRING_LIST(V)                             \
V( ZENOH_DECL_KEYEXPR, 0x00, "Declare KeyExpr" )                                                \
V( ZENOH_DECL_UKEYEXPR, 0x01, "Undeclare KeyExpr" )                                        \
V( ZENOH_DECL_SUB, 0x02, "Declare Subscriber" )                                              \
V( ZENOH_DECL_USUB, 0x03, "Undeclare Subscriber" )                                          \
V( ZENOH_DECL_QUER, 0x04, "Declare Queryable" )                                    \
V( ZENOH_DECL_UQUER, 0x05, "Undeclare Queryable" )                                    \
V( ZENOH_DECL_TOK, 0x06, "Declare Token" )                                    \
V( ZENOH_DECL_UTOK, 0x07, "Undeclare Token" )                                    \
V( ZENOH_DECL_FINAL, 0x1A, "DeclareFinal" )

VALUE_STRING_ENUM(zh_declare_type_names);
VALUE_STRING_ARRAY(zh_declare_type_names);

#define zh_what_am_i_names_VALUE_STRING_LIST(V) \
  V( ZENOH_ROUTER, 0b00, "Router" ) \
  V( ZENOH_PEER, 0b01, "Peer" ) \
  V( ZENOH_CLIENT, 0b10, "Client" )

VALUE_STRING_ARRAY(zh_what_am_i_names);

// Fields
static int hf_zenoh_transport_msg_type;
static int hf_zenoh_net_msg_type;
//static int hf_zenoh_declare_type;
static int hf_zenoh_proto_version;
static int hf_what_am_i;
static int hf_zid;
static int hf_sn_res;
static int hf_id_res;
static int hf_batch_size;
static int hf_lease_time;
static int hf_sn;
static int hf_cookie;
static int hf_ext_compression;
static int hf_reliable;
int hf_ext_unit;
int hf_ext_z64;
int hf_ext_zbuf;
int hf_key_expr;
int hf_key_expr_scope;
int hf_key_expr_suffix;
static int hf_key_expr_id;
static int hf_interest;
static int hf_sub_id;
static int hf_token_id;
int ett_zenoh;

static hf_register_info hf[] = {
  { &hf_zenoh_transport_msg_type,
      { "Transport message type", "zenohc.transport.type",
      FT_UINT8, BASE_DEC,
      VALS(zh_transport_msg_type_names), 0x1F,
      NULL, HFILL }
  },
{ &hf_zenoh_net_msg_type,
    { "Network message type", "zenohc.net.type",
    FT_UINT8, BASE_DEC,
    VALS(zh_net_msg_type_names), 0x1F,
    NULL, HFILL }
},
/*{ &hf_zenoh_declare_type,
    { "Declare type", "zenohc.decl.type",
    FT_UINT8, BASE_DEC,
    VALS(zh_declare_type_names), 0x1F,
    NULL, HFILL }
},*/
{&hf_zenoh_proto_version,
     {"Protocol version", "zenohc.version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
    {&hf_what_am_i,
     {"What A I", "zenohc.wai", FT_UINT8, BASE_DEC, VALS(zh_what_am_i_names), 0b11, NULL, HFILL}},
    {&hf_zid, {"ZID", "zenohc.zid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
    {&hf_sn_res, "SN resolution", "zenohc.sn_res", FT_UINT8, BASE_DEC, NULL, 0b11, NULL, HFILL},
    {&hf_id_res, "Request ID resolution", "zenohc.id_res", FT_UINT8, BASE_DEC, NULL, 0b1100, NULL, HFILL},
    {&hf_batch_size, "Batch size", "zenohc.batch_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL},
    {&hf_lease_time, "Lease time", "zenohc.lease_time", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_sn, "Serial number", "zenohc.sn", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_cookie, "Cookie", "zenohc.cookie", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_ext_unit, ")", "zenohc.ext", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_ext_z64, ")", "zenohc.ext.z64", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_ext_zbuf, ")", "zenohc.ext.zbuf", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_ext_compression, "Compression", "zenohc.ext.compression", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_reliable, "Reliable", "zenohc.transport.reliable", FT_BOOLEAN, 8, NULL, 1 << 5, NULL, HFILL},
{&hf_key_expr, "Key Expr", "zenohc.key_expr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_key_expr_scope, "Key Expr scope", "zenohc.key_expr.scope", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_key_expr_suffix, "Key Expr suffix", "zenohc.key_expr.suffix", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_key_expr_id, "Key Expr ID", "zenohc.key_expr.id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_interest, "Interest ID", "zenohc.interest_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_sub_id, "Subscription ID", "zenohc.sub_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_token_id, "Token ID", "zenohc.token_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
};

static int dissect_declare_keyexpr(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_named = (msg_header & 0x20) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  uint64_t expr_id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_key_expr_id, NULL, &expr_id);
  const char *res;
  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_named, true, &res);

  if (res)
    register_key_expr(pinfo, expr_id, res);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  return offset;
}

static int dissect_declare_subscriber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_named = (msg_header & 0x20) != 0;
  const bool has_mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  uint64_t expr_id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_sub_id, NULL, &expr_id);
  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_named, has_mapping, NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  return offset;
}

static int dissect_declare_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_named = (msg_header & 0x20) != 0;
  const bool has_mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  uint64_t expr_id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_token_id, NULL, &expr_id);
  const char *res;
  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_named, has_mapping, &res);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  return offset;
}

static int dissect_declare_queryable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_named = (msg_header & 0x20) != 0;
  const bool has_mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  ++offset;
  read_zint(tvb, &offset);

  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_named, has_mapping,
                            NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  return offset;
}

static int dissect_declare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_interest = (msg_header & 0x20) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  if (has_interest)
    offset = dissect_zint(tvb, tree, offset, hf_interest, NULL, NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  const uint8_t decl_header = tvb_get_uint8(tvb, offset);
  const uint8_t decl_type = decl_header & 0x1f;

  char const *str = try_val_to_str(decl_type, zh_declare_type_names);
  if (str)
    proto_item_set_text(proto_tree_get_parent(tree), "%s", str);

  switch (decl_type) {
  case ZENOH_DECL_KEYEXPR: return dissect_declare_keyexpr(tvb, pinfo, tree, offset, data);
  case ZENOH_DECL_SUB: return dissect_declare_subscriber(tvb, pinfo, tree, offset, data);
  case ZENOH_DECL_TOK: return dissect_declare_token(tvb, pinfo, tree, offset, data);
  case ZENOH_DECL_QUER: return dissect_declare_queryable(tvb, pinfo, tree, offset, data);
  default: return (int)tvb_reported_length(tvb);
  }
}

static int dissect_push(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_suffix = (msg_header & 0x20) != 0;
  const bool mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  offset = dissect_key_expr(tvb, pinfo, tree, offset + 1, has_suffix, mapping,
                            NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  return (int)tvb_reported_length(tvb);
}

static int dissect_net_message(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const uint8_t msg_type = msg_header & 0x1F;
  char const *type_str = try_val_to_str(msg_type, zh_net_msg_type_names);
  proto_item *subtree_item;
  proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_zenoh, &subtree_item, type_str ? type_str : "Unknown");
  if (type_str == NULL)
    proto_item_append_text(subtree_item, " (%u)", msg_type);

  col_append_str(pinfo->cinfo, COL_INFO, type_str ? type_str : "Unknown");

  switch (msg_type) {
  case ZENOH_NET_DECLARE: offset = dissect_declare(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_PUSH: offset = dissect_push(tvb, pinfo, subtree, offset, data); break;
  default: return (int)tvb_reported_length(tvb);
  }

  proto_item_set_end(subtree_item, tvb, offset);
  return offset;
}

static int dissect_transport_frame(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void *data) {
  col_append_str(pinfo->cinfo, COL_INFO, ", ");
  const uint8_t msg_header = tvb_get_uint8(tvb, 0);
  const bool has_exts = (msg_header & 0x80) != 0;
  proto_tree_add_item(tree, hf_reliable, tvb, 0, 1, ENC_NA);

  int offset = dissect_zint(tvb, tree, 1, hf_sn, NULL, NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);

  int tvb_len = (int)tvb_reported_length(tvb);
  while (offset + 1 < tvb_len) {
    offset = dissect_net_message(tvb, pinfo, tree, offset, data);
    if (offset + 1 < tvb_len)
      col_append_str(pinfo->cinfo, COL_INFO, ", ");
  }
  return offset;
}

static void dissect_open_compression(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length) {
  proto_tree_add_item(tree, hf_ext_compression, tvb, offset, 1, ENC_NA);
}

static struct ext_dissector_table_entry transport_open_exts[] = {
  {4, &dissect_open_compression},
  {0, NULL},
};

static int dissect_transport_open(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, 0);
  const bool is_ack = (msg_header & 0x20) != 0;
  const bool lease_period_s = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  col_append_str(pinfo->cinfo, COL_INFO, is_ack ? ", OpenAck" : ", OpenSyn");

  proto_item *lease_period_item;
  int offset = dissect_zint(tvb, tree, 1, hf_lease_time, &lease_period_item, NULL);
  proto_item_append_text(lease_period_item, lease_period_s ? "s" : "ms");

  offset = dissect_zint(tvb, tree, offset, hf_sn, NULL, NULL);

  if (!is_ack) {
    int cookie_length = (int)read_zint(tvb, &offset);
    proto_tree_add_item(tree, hf_cookie, tvb, offset, cookie_length, ENC_NA);
    offset += cookie_length;
  }

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, transport_open_exts);

  return offset;
}

static int dissect_transport_init(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, 0);
  const bool is_ack = (msg_header & 0x20) != 0;
  const bool has_size = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  col_append_str(pinfo->cinfo, COL_INFO, is_ack ? ", InitAck" : ", InitSyn");
  proto_tree_add_item(tree, hf_zenoh_proto_version, tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_what_am_i, tvb, 2, 1, ENC_LITTLE_ENDIAN);

  const uint8_t zid_len = 1 + (tvb_get_uint8(tvb, 2) >> 4);
  proto_item *zid_item = proto_tree_add_item(tree, hf_zid, tvb, 3, zid_len, ENC_NA);
  proto_item_set_text(zid_item, "ZID: ");
  char zid_buff[2 * MAX_ZID_SIZE + 1];
  for (int i = 0; i < zid_len; ++i) {
    snprintf(zid_buff + (2 * i), 3, "%02x", (unsigned)tvb_get_uint8(tvb, 3 + zid_len - 1 - i));
  }
  proto_item_append_text(zid_item, "%s", zid_buff);
  register_zid(pinfo, zid_buff);

  int offset = 3 + zid_len;
  if (has_size) {
    proto_tree_add_item(tree, hf_sn_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_id_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_batch_size, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
    offset += 3;
  }

  if (is_ack) {
//  TODO
  }

  // TODO Remove !is_ack
  if (!is_ack && has_exts) {
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL);
  }

  return offset;
}

static int dissect_transport_msg(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void *data) {
  proto_item *ti = proto_tree_add_item(tree, proto_zenoh, tvb, 0, -1, ENC_NA);
  proto_tree *proto_tree = proto_item_add_subtree(ti, ett_zenoh);
  proto_tree_add_item(proto_tree, hf_zenoh_transport_msg_type, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  uint8_t msg_header = tvb_get_uint8(tvb, 0);
  uint8_t msg_type = msg_header & 0x1F;

  switch (msg_type) {
  case ZENOH_TRANSPORT_INIT:
    return dissect_transport_init(tvb, pinfo, proto_tree, data);
  case ZENOH_TRANSPORT_OPEN:
    return dissect_transport_open(tvb, pinfo, proto_tree, data);
  case ZENOH_TRANSPORT_FRAME:
    return dissect_transport_frame(tvb, pinfo, proto_tree, data);
  default: return (int)tvb_reported_length(tvb);
  }
}

static int
dissect_zenoh_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  unsigned reported_length = tvb_reported_length(tvb);
  if (reported_length < 2)
    return (int)reported_length - 2;
  unsigned pdu_length = tvb_get_uint16(tvb, 0, ENC_LITTLE_ENDIAN);
  if (reported_length < 2 + pdu_length)
    return (int)reported_length - 2 - (int)pdu_length;

  tvbuff_t *subset = tvb_new_subset_length(tvb, 2, (int)pdu_length);
  return dissect_transport_msg(subset, pinfo, tree, data);
}

static unsigned zenoh_get_pdu_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
  unsigned pdu_length = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
  return 2 + pdu_length;
}

static int
dissect_zenoh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  const char *curr_protocol_col = col_get_text(pinfo->cinfo, COL_PROTOCOL);
  if (curr_protocol_col == NULL || strcmp(curr_protocol_col, "Zenoh") != 0) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zenoh");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%hu → %hu", pinfo->srcport, pinfo->destport);
  }

  int tvb_len = (int)tvb_reported_length(tvb);
  if (pinfo->can_desegment > 0) {
    if (pinfo->ptype == PT_TCP) {
      tcp_dissect_pdus(tvb, pinfo, tree, true, 2, &zenoh_get_pdu_length, &dissect_zenoh_pdu, data);
      return (int)tvb_reported_length(tvb);
    }

    int offset = 0;

    // Do a first pass to be sure we have all the PDUs.
    while (offset != tvb_len) {
      if (tvb_len - offset < 2)
        return -2;
      uint16_t segment_length = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
      offset += 2;

      if (tvb_len - offset < segment_length)
        return segment_length - (tvb_len - offset);

      offset += segment_length;
    }

    offset = 0;
    while (offset != tvb_len) {
      if (tvb_len - offset < 2)
        return -2;
      uint16_t segment_length = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
      offset += 2;

      if (tvb_len - offset < segment_length)
        return segment_length - (tvb_len - offset);

      tvbuff_t *subset = tvb_new_subset_length(tvb, offset, segment_length);
      dissect_transport_msg(subset, pinfo, tree, data);
      offset += segment_length;
    }

    return offset;
  }

  return dissect_transport_msg(tvb, pinfo, tree, data);
}

static void proto_register_zenoh(void)
{
  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_zenoh
  };

  proto_zenoh = proto_register_protocol (
      "Zenoh Protocol", /* protocol name        */
      "Zenoh",          /* protocol short name  */
      "zenohc"           /* protocol filter_name */
      );

  proto_register_field_array(proto_zenoh, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  zenoh_handle = register_dissector_with_description("zenohc", "The Zenoh protocol dissector", dissect_zenoh, proto_zenoh);
}

static void proto_reg_handoff_zenoh(void)
{
  dissector_add_uint("tcp.port", 7447, zenoh_handle);
  dissector_add_uint("tcp.port", 7448, zenoh_handle);
  dissector_add_uint("udp.port", 7447, zenoh_handle);
  dissector_add_uint("udp.port", 7448, zenoh_handle);
}

WS_DLL_PUBLIC_DEF void plugin_register()
{
  static proto_plugin plugin_zenoh;
  plugin_zenoh.register_protoinfo = proto_register_zenoh;
  plugin_zenoh.register_handoff = proto_reg_handoff_zenoh;
  proto_register_plugin(&plugin_zenoh);
}
