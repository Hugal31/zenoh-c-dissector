#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <wireshark/ws_version.h>

#include "conv.h"
#include "exts.h"
#include "fields.h"
#include "key_exprs.h"
#include "lz4.h"
#include "utils.h"

WS_DLL_PUBLIC_DEF char const *plugin_version = "0.1.0";
WS_DLL_PUBLIC_DEF int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF int plugin_want_minor = WIRESHARK_VERSION_MINOR;

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

#define zh_push_body_names_VALUE_STRING_LIST(V)                                \
  V( ZENOH_PUSH_PUT, 0x01, "Put" )                                              \
  V( ZENOH_PUSH_DEL, 0x02, "Del" )

VALUE_STRING_ARRAY(zh_push_body_names);
VALUE_STRING_ENUM(zh_push_body_names);

#define zh_what_am_i_names_VALUE_STRING_LIST(V) \
  V( ZENOH_ROUTER, 0b00, "Router" ) \
  V( ZENOH_PEER, 0b01, "Peer" ) \
  V( ZENOH_CLIENT, 0b10, "Client" )

VALUE_STRING_ARRAY(zh_what_am_i_names);

#define zh_what_am_i_flags_names_VALUE_STRING_LIST(V)                          \
  V( ZENOH_F_ROUTER, 0b001, "Router" )                                             \
  V( ZENOH_F_PEER, 0b010, "Peer" )                                                 \
  V( ZENOH_F_CLIENT, 0b100, "Client" ) \
  V( ZENOH_F_ROUTER, 0b011, "Router|Peer" )

VALUE_STRING_ARRAY(zh_what_am_i_flags_names);

#define zh_consolidation_names_VALUE_STRING_LIST(V) \
  V( ZENOH_CONSOLIDATION_AUTO, 0, "Auto" ) \
  V( ZENOH_CONSOLIDATION_NONE, 1, "None" ) \
  V( ZENOH_CONSOLIDATION_MONOTONIC, 2, "Monotonic" ) \
  V( ZENOH_CONSOLIDATION_LATEST, 3, "Latest" )
VALUE_STRING_ARRAY(zh_consolidation_names);

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
static int hf_query_id;
static int hf_interest;
static int hf_sub_id;
static int hf_token_id;
static int hf_timestamp;
static int hf_timestamp_hlc;
static int hf_encoding_id;
static int hf_encoding_schema;
static int hf_put_payload;
static int hf_query_payload;
static int hf_consolidation;
static int hf_keep_alive;
static int hf_net_oam;
static int hf_net_oam_id;
static int hf_net_oam_data;
static int hf_net_oam_payload;
static int hf_linkstate;
static int hf_linkstate_psid;
static int hf_linkstate_sn;
static int hf_linkstate_zid;
static int hf_linkstate_wai;
static int hf_linkstate_locator;
static int hf_linkstate_link;
static int hf_rmw_zenoh_sequence_number;
static int hf_rmw_zenoh_timestamp;
static int hf_rmw_zenoh_source_gid;
static int hf_reply_to_query;
static int hf_query_to_reply;
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
{&hf_query_id, "Query ID", "zenohc.query_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_interest, "Interest ID", "zenohc.interest_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_sub_id, "Subscription ID", "zenohc.sub_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_token_id, "Token ID", "zenohc.token_id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_timestamp, "Timestamp", "zenohc.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL},
{&hf_timestamp_hlc, "Timestamp HLC ID", "zenohc.timestamp.hlc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_encoding_id, "Encoding ID", "zenohc.encoding.id", FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL},
{&hf_encoding_schema, "Encoding Schema", "zenohc.encoding.schema", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_put_payload, "Payload", "zenohc.put.payload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_query_payload, "Parameters", "zenohc.query.payload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
  {&hf_consolidation, "Consolidation", "zenohc.query.consolidation", FT_UINT8, BASE_DEC, VALS(zh_consolidation_names), 0, NULL, HFILL},
  {&hf_keep_alive, "KeepAlive", "zenohc.keep_alive", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_net_oam, "OAM", "zenohc.net.oam", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_net_oam_id, "OAM ID", "zenohc.net.oam.id", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_net_oam_data, "OAM Data", "zenohc.net.oam.data", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_net_oam_payload, "OAM Payload", "zenohc.net.oam.payload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_linkstate, "Linkstate", "zenohc.linkstate", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_linkstate_psid, "Linkstate PSID", "zenohc.linkstate.psid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_linkstate_sn, "Linkstate SN", "zenohc.linkstate.sn", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_linkstate_zid, "ZID", "zenohc.linkstate.zid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_linkstate_wai, "What Am I", "zenohc.linkstate.wai", FT_UINT8, BASE_DEC, VALS(zh_what_am_i_flags_names), 0, NULL, HFILL},
{&hf_linkstate_locator, "Locator", "zenohc.linkstate.locator", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_linkstate_link, "Link", "zenohc.linkstate.link", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_rmw_zenoh_sequence_number, "Sequence number", "zenohc.rmw_zenoh.sn", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL},
{&hf_rmw_zenoh_timestamp, "Timestamp", "zenohc.rmw_zenoh.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL},
{&hf_rmw_zenoh_source_gid, "Source GID", "zenohc.rmw_zenoh.source_gid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_reply_to_query, "Reply in", "zenohc.query.reply_frame", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL},
{&hf_query_to_reply, "Query in", "zenohc.reply.query_frame", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL},
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
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

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
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

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
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

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
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

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
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

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

void dissect_attachment(tvbuff_t * tvb, packet_info *pinfo, proto_tree * tree, int offset, int length, void *data) {
  // Try to dissect rmw_zenoh style attachement: strings + U64.
  const int all_start = offset;
  const int end = offset + length;
  proto_tree *subtree = NULL;
  while (offset < end) {
    const int start = offset;
    int str_len = (int)read_zint(tvb, &offset);

    if (offset + str_len > end)
      return;

    char *key = wmem_alloc(pinfo->pool, str_len + 1);
    tvb_memcpy(tvb, key, offset, str_len);
    key[str_len] = '\0';
    offset += str_len;

    if (!subtree)
      subtree = proto_tree_add_subtree(tree, tvb, all_start, length, ett_zenoh, NULL, "Attachments");

    if (strcmp(key, "sequence_number") == 0) {
      proto_tree_add_item(subtree, hf_rmw_zenoh_sequence_number, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;
    } else if (strcmp(key, "source_timestamp") == 0) {
      const uint64_t value = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN);
      nstime_t time;
      time.secs = (time_t)(value / 1000000000);
      time.nsecs = (int)(value % 1000000000);
      proto_tree_add_time(subtree, hf_rmw_zenoh_timestamp, tvb, offset, 8, &time);
      offset += 8;
    } else if (strcmp(key, "source_gid") == 0) {
      proto_tree_add_item(subtree, hf_rmw_zenoh_source_gid, tvb, offset, end - offset, ENC_NA);
      offset = end;
    } else {
      offset = end;
    }
    wmem_free(pinfo->pool, key);
  }
}

static struct ext_dissector_table_entry put_exts[] = {
  {3, &dissect_attachment},
  {0, NULL},
};

static int dissect_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_timestamp = (msg_header & 0x20) != 0;
  const bool has_encoding = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  ++offset;

  if (has_timestamp) {
    int start = offset;
    uint64_t timestamp = read_zint(tvb, &offset);
    uint64_t timestamp_s = timestamp >> 32;
    uint64_t timestamp_ns = ((timestamp & 0xFFFFFFFF) * 1000000000ULL) / (1ULL << 32);
    nstime_t time;
    time.secs = (time_t)timestamp_s;
    time.nsecs = (int)timestamp_ns;
    proto_item *timestamp_item = proto_tree_add_time(tree, hf_timestamp, tvb, start, offset - start, &time);
    proto_tree *timestamp_tree = proto_item_add_subtree(timestamp_item, ett_zenoh);
    //offset = dissect_zint(tvb, tree, offset, hf_timestamp_hlc, NULL, NULL);
    int hlc_len = (int)read_zint(tvb, &offset);
    proto_tree_add_item(timestamp_tree, hf_timestamp_hlc, tvb, offset, hlc_len, ENC_NA);
    offset += hlc_len;
  }

  if (has_encoding) {
    const uint8_t enc_header = tvb_get_uint8(tvb, offset);
    const bool has_schema = enc_header & 0x1;
    const int start = offset;
    ++offset;
    int schema_len = 0;
    if (has_schema) {
      schema_len = (int)read_zint(tvb, &offset);
    }
    proto_item *schema_item;
    proto_tree *schema_tree = proto_tree_add_subtree(tree, tvb, start, offset - start, ett_zenoh, &schema_item, "Schema ");
    proto_item_append_text(schema_item, "%u", enc_header >> 1);
    proto_tree_add_item(schema_tree, hf_encoding_id, tvb, start, 1, ENC_LITTLE_ENDIAN);
    if (has_schema) {
      proto_tree_add_item(schema_tree, hf_encoding_schema, tvb, start + 1, schema_len, ENC_NA);
    }
  }

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, put_exts, NULL);

  int payload_len = (int)read_zint(tvb, &offset);
  proto_tree_add_item(tree, hf_put_payload, tvb, offset, payload_len, ENC_NA);
  offset += payload_len;

  return offset;
}

static int dissect_response_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        int offset, void *data) {
  const uint8_t body_header = tvb_get_uint8(tvb, offset);
  switch (body_header & 0x1f) {
  case ZENOH_PUSH_PUT: return dissect_put(tvb, pinfo, tree, offset, data);
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
    offset = dissect_exts(tvb, pinfo, tree, offset, default_ext_dissector_table, NULL);

  return dissect_response_body(tvb, pinfo, tree, offset, data);
}

static int dissect_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_consolidation = (msg_header & 0x20) != 0;
  const bool has_parameters = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  ++offset;
  if (has_consolidation) {
    const int start = offset;
    uint8_t consolidation = (uint8_t)read_zint(tvb, &offset);
    proto_tree_add_uint(tree, hf_consolidation, tvb, start, offset - start, consolidation);
  }

  if (has_parameters) {
    int payload_len = (int)read_zint(tvb, &offset);
    proto_tree_add_item(tree, hf_query_payload, tvb, offset, payload_len, ENC_NA);
    offset += payload_len;
  }

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

  return offset;
}

static int dissect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_suffix = (msg_header & 0x20) != 0;
  const bool mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  // TODO Link query and reply
  uint64_t id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_query_id, NULL, &id);

  register_query(pinfo, (uint32_t)id);
  wmem_list_t *replies = get_replies(pinfo, (uint32_t)id, true);
  for (wmem_list_frame_t *frame = replies ? wmem_list_head(replies) : NULL; frame != NULL;
       frame = wmem_list_frame_next(frame)) {
    uint32_t num = (uint32_t)(uint64_t)wmem_list_frame_data(frame);
    proto_item *id_item = proto_tree_add_uint(tree, hf_reply_to_query, tvb, 0, 0, num);
    proto_item_set_generated(id_item);
  }

  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_suffix, mapping,
                            NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, default_ext_dissector_table, NULL);

  return dissect_query(tvb, pinfo, tree, offset, data);
}

static int dissect_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_consolidation = (msg_header & 0x20) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  ++offset;
  if (has_consolidation) {
    const int start = offset;
    uint8_t consolidation = (uint8_t)read_zint(tvb, &offset);
    proto_tree_add_uint(tree, hf_consolidation, tvb, start, offset - start, consolidation);
  }

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

  return dissect_response_body(tvb, pinfo, tree, offset, data);
}

static int dissect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_suffix = (msg_header & 0x20) != 0;
  const bool mapping = (msg_header & 0x40) != 0;
  const bool has_exts = (msg_header & 0x80) != 0;

  uint64_t id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_query_id, NULL, &id);

  register_reply(pinfo, (uint32_t)id);
  wmem_list_t *queries = get_queries(pinfo, (uint32_t)id, false);
  for (wmem_list_frame_t *frame = queries ? wmem_list_head(queries) : NULL; frame != NULL;
         frame = wmem_list_frame_next(frame)) {
    uint32_t num = (uint32_t)(uint64_t)wmem_list_frame_data(frame);
    proto_item *id_item = proto_tree_add_uint(tree, hf_query_to_reply, tvb, 0, 0, num);
    proto_item_set_generated(id_item);
  }

  offset = dissect_key_expr(tvb, pinfo, tree, offset, has_suffix, mapping,
                            NULL);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, default_ext_dissector_table, NULL);

  const uint8_t payload_header = tvb_get_uint8(tvb, offset);
  switch (payload_header & 0x1F) {
  case 4: return dissect_reply(tvb, pinfo, tree, offset, data);
  default: return tvb_reported_length(tvb);
  }
}

static int dissect_response_final(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const bool has_exts = (msg_header & 0x80) != 0;

  uint64_t id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_query_id, NULL, &id);

  register_reply(pinfo, (uint32_t)id);
  wmem_list_t *queries = get_queries(pinfo, (uint32_t)id, false);
  for (wmem_list_frame_t *frame = queries ? wmem_list_head(queries) : NULL; frame != NULL;
         frame = wmem_list_frame_next(frame)) {
    uint32_t num = (uint32_t)(uint64_t)wmem_list_frame_data(frame);
    proto_item *id_item = proto_tree_add_uint(tree, hf_query_to_reply, tvb, 0, 0, num);
    proto_item_set_generated(id_item);
  }

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, NULL);

  return offset;
}

static int dissect_linkstate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t header = tvb_get_uint8(tvb, offset);
  const bool has_zid = header & 0b001;
  const bool has_what_am_i = header & 0b010;
  const bool has_locator = header & 0b100;

  offset = dissect_zint(tvb, tree, offset + 1, hf_linkstate_psid, NULL, NULL);
  offset = dissect_zint(tvb, tree, offset, hf_linkstate_sn, NULL, NULL);
  if (has_zid) {
    int zid_length = (int)read_zint(tvb, &offset);
    offset = dissect_zid(tvb, tree, hf_linkstate_zid, offset, zid_length, NULL);
  }

  if (has_what_am_i)
    proto_tree_add_item(tree, hf_linkstate_wai, tvb, offset++, 1, ENC_LITTLE_ENDIAN);

  if (has_locator) {
    uint64_t nlocators = read_zint(tvb, &offset);
    for (uint64_t i = 0; i < nlocators; ++i) {
      int locator_length = (int)read_zint(tvb, &offset);
      proto_tree_add_item(tree, hf_linkstate_locator, tvb, offset, locator_length, ENC_ASCII);
      offset += locator_length;
    }
  }

  const uint64_t n_links = read_zint(tvb, &offset);
  for (uint64_t i = 0; i < n_links; ++i) {
    offset = dissect_zint(tvb, tree, offset, hf_linkstate_link, NULL, NULL);
  }
  return offset;
}

static int dissect_linkstate_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint64_t n_linkstates = read_zint(tvb, &offset);
  const int tvb_len = (int)tvb_reported_length(tvb);
  for (uint64_t i = 0; i < n_linkstates; ++i && offset + 1 < tvb_len) {
    proto_item *linkstate_item = proto_tree_add_item(tree, hf_linkstate, tvb, offset, -1, ENC_NA);
    proto_tree *linkstate_tree = proto_item_add_subtree(linkstate_item, ett_zenoh);
    offset = dissect_linkstate(tvb, pinfo, linkstate_tree, offset, NULL);
    proto_item_set_end(linkstate_item, tvb, offset);
  }
  return offset;
}

static int dissect_net_oam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const uint8_t encoding = (msg_header >> 5) & 0b11;
  const bool has_exts = msg_header & 0x80;

  uint64_t id;
  offset = dissect_zint(tvb, tree, offset + 1, hf_net_oam_id, NULL, &id);

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, default_ext_dissector_table, NULL);

  switch (encoding) {
  default:
  case 0: break;
  case 0b01:
    offset = dissect_zint(tvb, tree, offset, hf_net_oam_data, NULL, NULL);
    break;

  case 0b10: {
    int payload_length = (int)read_zint(tvb, &offset);
    proto_item *payload_item = proto_tree_add_item(tree, hf_net_oam_payload, tvb, offset, payload_length, ENC_NA);
    if (id == 1)
      dissect_linkstate_list(tvb, pinfo, proto_item_add_subtree(payload_item, ett_zenoh), offset, data);
    offset += payload_length;
  }
  }

  return offset;
}

static int dissect_net_message(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, int offset, void *data) {
  const uint8_t msg_header = tvb_get_uint8(tvb, offset);
  const uint8_t msg_type = msg_header & 0x1F;
  char const *type_str = try_val_to_str(msg_type, zh_net_msg_type_names);
  int hfindex;
  switch (msg_type) {
  default: hfindex = hf_text_only; break;
  case ZENOH_NET_OAM: hfindex = hf_net_oam; break;
  }
  proto_item *subtree_item = proto_tree_add_item(tree, hfindex, tvb, offset, 1, ENC_NA);
  proto_item_set_text(subtree_item, "%s", type_str ? type_str : "Unknown");
  proto_tree *subtree = proto_item_add_subtree(subtree_item, ett_zenoh);

  if (type_str == NULL)
    proto_item_append_text(subtree_item, " (%u)", msg_type);

  col_append_str(pinfo->cinfo, COL_INFO, type_str ? type_str : "Unknown");

  switch (msg_type) {
  case ZENOH_NET_DECLARE: offset = dissect_declare(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_PUSH: offset = dissect_push(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_REQUEST: offset = dissect_request(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_RESPONSE: offset = dissect_response(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_RESPONSE_FINAL: offset = dissect_response_final(tvb, pinfo, subtree, offset, data); break;
  case ZENOH_NET_OAM: offset = dissect_net_oam(tvb, pinfo, subtree, offset, data); break;
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
    offset = dissect_exts(tvb, pinfo, tree, offset, default_ext_dissector_table, NULL);

  int tvb_len = (int)tvb_reported_length(tvb);
  while (offset + 1 < tvb_len) {
    offset = dissect_net_message(tvb, pinfo, tree, offset, data);
    if (offset + 1 < tvb_len)
      col_append_str(pinfo->cinfo, COL_INFO, ", ");
  }
  return offset;
}

struct zenoh_open_data {
  bool is_ack;
};

static void dissect_open_compression(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, void *data) {
  proto_tree_add_item(tree, hf_ext_compression, tvb, offset, 1, ENC_NA);
  const struct zenoh_open_data *open_data = (const struct zenoh_open_data*)data;
  if (open_data->is_ack) {
    struct net_conv_data_t *conv_data = get_net_conv_data(pinfo);
    if (conv_data)
      conv_data->compression_start = pinfo->num;
  }
}

static struct ext_dissector_table_entry transport_open_exts[] = {
  {6, &dissect_open_compression},
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

  struct zenoh_open_data open_data;
  open_data.is_ack = is_ack;

  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, transport_open_exts, &open_data);

  if (is_ack) {
    struct net_conv_data_t *conv_data = get_net_conv_data(pinfo);
    if (conv_data->compression_negotiated)
      conv_data->compression_start = pinfo->num;
  }

  return offset;
}

struct zenoh_init_data {
  bool is_ack;
};

static void dissect_init_compression(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, void *data) {
  proto_tree_add_item(tree, hf_ext_compression, tvb, offset, 1, ENC_NA);
  const struct zenoh_init_data *init_data = data;
  if (init_data->is_ack) {
    struct net_conv_data_t *conv_data = get_net_conv_data(pinfo);
    // printf("Compression negotiated in %u (conv data is %p)\n", pinfo->num, conv_data);
    if (conv_data)
      conv_data->compression_negotiated = true;
  }
}

static struct ext_dissector_table_entry transport_init_exts[] = {
  {6, &dissect_init_compression},
  {0, NULL},
};

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
  char zid_buff[2 * MAX_ZID_SIZE + 1];
  dissect_zid(tvb, tree, hf_zid, 3, zid_len, zid_buff);
  register_zid(pinfo, zid_buff);

  int offset = 3 + zid_len;
  if (has_size) {
    proto_tree_add_item(tree, hf_sn_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_id_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_batch_size, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
    offset += 3;
  }

  if (is_ack) {
    int cookie_length = (int)read_zint(tvb, &offset);
    proto_tree_add_item(tree, hf_cookie, tvb, offset, cookie_length, ENC_NA);
    offset += cookie_length;
  }

  if (has_exts) {
    struct zenoh_init_data init_data;
    init_data.is_ack = is_ack;
    offset = dissect_exts(tvb, pinfo, tree, offset, transport_init_exts, &init_data);
  }

  return offset;
}

static int dissect_transport_keep_alive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  col_append_str(pinfo->cinfo, COL_INFO, ", KeepAlive");
  uint8_t msg_header = tvb_get_uint8(tvb, 0);
  bool has_exts = msg_header & 0x80;

  int offset = 1;
  if (has_exts)
    offset = dissect_exts(tvb, pinfo, tree, offset, NULL, data);

  proto_tree_add_item(tree, hf_keep_alive, tvb, 0, offset, ENC_NA);

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
  case ZENOH_TRANSPORT_KEEP_ALIVE:
    return dissect_transport_keep_alive(tvb, pinfo, proto_tree, data);
  default: return (int)tvb_reported_length(tvb);
  }
}

static int dissect_zenoh_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  const int tvb_len = (int)tvb_reported_length(tvb);

  const struct net_conv_data_t *conv_data = get_net_conv_data(pinfo);
  if (conv_data->compression_start < pinfo->num) {
    uint8_t compression_header = tvb_get_uint8(tvb, 0);
    if (compression_header == 1) {
      tvbuff_t *uncompressed = zenoh_tvb_uncompress_lz4(tvb, 1, tvb_len - 1);
      if (!uncompressed) {
        col_add_str(pinfo->cinfo, COL_INFO, " Could not uncompress");
        return tvb_len;
      }

      tvb_set_child_real_data_tvbuff(tvb, uncompressed);
      add_new_data_source(pinfo, uncompressed, "LZ4 Uncompressed");
      return dissect_transport_msg(uncompressed, pinfo, tree, data);
    } else {
      tvbuff_t *subset = tvb_new_subset_length(tvb, 1, tvb_len - 1);
      return dissect_transport_msg(subset, pinfo, tree, data);
    }
  }

  return dissect_transport_msg(tvb, pinfo, tree, data);
}

static int
dissect_zenoh_pdu_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  unsigned reported_length = tvb_reported_length(tvb);
  if (reported_length < 2)
    return (int)reported_length - 2;
  unsigned pdu_length = tvb_get_uint16(tvb, 0, ENC_LITTLE_ENDIAN);
  if (reported_length < 2 + pdu_length)
    return (int)reported_length - 2 - (int)pdu_length;

  tvbuff_t *subset = tvb_new_subset_length(tvb, 2, (int)pdu_length);
  return dissect_zenoh_pdu(subset, pinfo, tree, data);
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
      tcp_dissect_pdus(tvb, pinfo, tree, true, 2, &zenoh_get_pdu_length, &dissect_zenoh_pdu_stream, data);
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

  return dissect_zenoh_pdu(tvb, pinfo, tree, data);
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
