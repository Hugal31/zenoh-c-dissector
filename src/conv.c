#include "conv.h"

#include "fields.h"

#include <epan/conversation.h>

static struct zenoh_conv_data_t *zenoh_conv_new(wmem_allocator_t *allocator) {
  struct zenoh_conv_data_t *conv =
      wmem_new0(allocator, struct zenoh_conv_data_t);
  for (int i = 0; i < 2; ++i) {
    conv->sides[i].expr_id_cache = wmem_tree_new(allocator);
    conv->sides[i].query_frame_num_cache = wmem_tree_new(allocator);
  }
  return conv;
}

static struct net_conv_data_t *net_conv_new(wmem_allocator_t *allocator) {
  struct net_conv_data_t *conv = wmem_new0(allocator, struct net_conv_data_t);
  conv->compression_start = ~0U;
  return conv;
}

// Return 0 or 1, an arbitrary order between the sender and the receiver.
static uint8_t is_low_or_high(const packet_info *pinfo) {
  if (pinfo->srcport < pinfo->destport)
    return 0;
  if (pinfo->srcport > pinfo->destport)
    return 1;

  return cmp_address(&pinfo->net_src, &pinfo->net_dst) < 0 ? 0 : 1;
}

struct zenoh_conv_data_t *get_zenoh_conv_data(const packet_info *pinfo) {
  const struct net_conv_data_t *net_conv_data = get_net_conv_data(pinfo);
  if (net_conv_data == NULL)
    return NULL;

  return net_conv_data->zenoh_conv_data;
}

struct net_conv_data_t *get_net_conv_data(const packet_info *pinfo) {
  conversation_t *net_conv = find_conversation_pinfo(pinfo, 0);
  struct net_conv_data_t *net_conv_data = conversation_get_proto_data(net_conv, proto_zenoh);
  if (net_conv_data == NULL) {
    net_conv_data = net_conv_new(wmem_file_scope());
    conversation_add_proto_data(net_conv, proto_zenoh, net_conv_data);
  }
  return net_conv_data;
}

void register_key_expr(const packet_info *pinfo, uint64_t expr_id,
                       const char *key_expr) {
  struct zenoh_conv_data_t *zconv = get_zenoh_conv_data(pinfo);
  if (!zconv)
    return;

  uint8_t low_or_high = is_low_or_high(pinfo);
  wmem_tree_t *cache = zconv->sides[low_or_high].expr_id_cache;
  DISSECTOR_ASSERT_HINT(expr_id < (2ULL<<32), "Expression ID too high");
  if (!wmem_tree_contains32(cache, expr_id)) {
    wmem_tree_insert32(cache, expr_id, wmem_strdup(wmem_file_scope(), key_expr));
    //printf("Registered key expression '%lu' '%s' for packet %d\n", expr_id, key_expr, pinfo->num);
  }
}

char const *get_key_expr(const packet_info *pinfo, uint64_t scope_id,
                         bool sender) {
  struct zenoh_conv_data_t *zconv = get_zenoh_conv_data(pinfo);
  if (!zconv)
    return NULL;

  uint8_t low_or_high = is_low_or_high(pinfo);
  if (!sender)
    low_or_high = !low_or_high;
  wmem_tree_t *cache = zconv->sides[low_or_high].expr_id_cache;
  const char *res = wmem_tree_lookup32(cache, scope_id);
  if (!res)
      printf("Failed to fetch expression '%lu' in packet %d\n", scope_id, pinfo->num);
  return res;
}

void register_zid(const packet_info *pinfo, const char *zid) {
  struct net_conv_data_t *net_conv_data = get_net_conv_data(pinfo);

  size_t low_or_high = is_low_or_high(pinfo);
  net_conv_data->zids[low_or_high] = wmem_strdup(wmem_file_scope(), zid);
  if (net_conv_data->zids[!low_or_high] != NULL) {
    const conversation_element_t elements[3] = {
      {CE_STRING, {.str_val = net_conv_data->zids[0]}},
      {CE_STRING, {.str_val = net_conv_data->zids[1]}},
      // Should we register the conv type?
      {CE_CONVERSATION_TYPE, {.conversation_type_val = proto_zenoh}}
    };

    conversation_t *zenoh_conv = find_conversation_full(pinfo->num, elements);
    if (!zenoh_conv) {
      zenoh_conv = conversation_new_full(pinfo->num, elements);
      conversation_add_proto_data(zenoh_conv, proto_zenoh, zenoh_conv_new(wmem_file_scope()));
    }
    struct zenoh_conv_data_t *zenoh_conv_data = conversation_get_proto_data(zenoh_conv, proto_zenoh);
    net_conv_data->zenoh_conv_data = zenoh_conv_data;
  }
}

struct zenoh_query_info_t *zenoh_query_info_new(wmem_allocator_t *allocator) {
  struct zenoh_query_info_t *ret =
      wmem_new(allocator, struct zenoh_query_info_t);
  ret->query_packets = wmem_list_new(allocator);
  ret->reply_packets = wmem_list_new(allocator);
  return ret;
}

static struct zenoh_query_info_t *get_query_info(const packet_info *pinfo, uint32_t query_id, bool sender) {
  struct zenoh_conv_data_t *conv_data = get_zenoh_conv_data(pinfo);
  if (!conv_data)
    return NULL;

  size_t low_or_high = is_low_or_high(pinfo);
  wmem_tree_t *tree = conv_data->sides[sender ? low_or_high : !low_or_high].query_frame_num_cache;
  struct zenoh_query_info_t *info = wmem_tree_lookup32(tree, query_id);
  if (!info) {
    info = zenoh_query_info_new(wmem_file_scope());
    wmem_tree_insert32(tree, query_id, info);
  }
  return info;
}

void register_query(const packet_info *pinfo, uint32_t query_id) {
  wmem_list_t *query_packets_list = get_queries(pinfo, query_id, true);
  if (!query_packets_list)
    return;

  if (!wmem_list_find(query_packets_list, (void*)pinfo->num))
    wmem_list_append(query_packets_list, (void*)pinfo->num);
}

void register_reply(const packet_info *pinfo, uint32_t reply_id) {
  wmem_list_t *replies_packets_list = get_replies(pinfo, reply_id, false);
  if (!replies_packets_list)
    return;

  if (!wmem_list_find(replies_packets_list, (void*)pinfo->num))
    wmem_list_append(replies_packets_list, (void*)pinfo->num);
}

wmem_list_t *get_queries(const packet_info *pinfo, uint32_t query_id, bool sender) {
  struct zenoh_query_info_t *info = get_query_info(pinfo, query_id, sender);
  if (!info)
    return NULL;

  return info->query_packets;
}

wmem_list_t *get_replies(const packet_info *pinfo, uint32_t reply_id,
                         bool sender) {
  struct zenoh_query_info_t *info = get_query_info(pinfo, reply_id, sender);
  if (!info)
    return NULL;

  return info->reply_packets;
}
