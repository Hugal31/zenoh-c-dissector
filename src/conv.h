#pragma once

#include <epan/packet.h>

struct zenoh_data_t {
  GHashTable *conversations;
};

struct zenoh_expr_id_cache_t {
  wmem_tree_t *tree;
};

struct zenoh_conv_data_t {
  struct zenoh_expr_id_cache_t expr_id_cache[2];
};

struct net_conv_data_t {
  const char *zids[2];
  struct zenoh_conv_data_t *zenoh_conv_data;
  bool compression_negotiated;
  uint32_t compression_start;
};

typedef struct zenoh_data_t zenoh_data_t;

struct zenoh_conv_data_t *get_zenoh_conv_data(const packet_info *pinfo);
struct net_conv_data_t *get_net_conv_data(const packet_info *pinfo);

char const *get_key_expr(const packet_info *pinfo, uint64_t scope_id,
                         bool sender);
void register_key_expr(const packet_info *pinfo, uint64_t expr_id,
                       const char *key_expr);
void register_zid(const packet_info *pinfo, const char *zid);
