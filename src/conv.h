#pragma once

#include <epan/packet.h>

struct zenoh_data_t {
  GHashTable *conversations;
};

typedef struct zenoh_data_t zenoh_data_t;

char const *get_key_expr(const packet_info *pinfo, uint64_t scope_id,
                         bool sender);
void register_key_expr(const packet_info *pinfo, uint64_t expr_id,
                       const char *key_expr);
void register_zid(const packet_info *pinfo, const char *zid);
