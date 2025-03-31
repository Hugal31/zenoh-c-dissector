#pragma once

#include <epan/packet.h>

struct zenoh_subscriber_info_t
{
    uint32_t declaration_packet_id;
    char *key_expr;
};

struct zenoh_queryable_info_t
{
    uint32_t declaration_packet_id;
    char *key_expr;
};

struct zenoh_token_info_t
{
    uint32_t declaration_packet_id;
    char *key_expr;
};

// Query data, stored in the sender side.
struct zenoh_query_info_t
{
    wmem_list_t *query_packets;
    wmem_list_t *reply_packets;
};

struct zenoh_conv_data_side_t
{
    /// Contains const char*
    wmem_tree_t *expr_id_cache;
    /// Contains struct zenoh_subscriber_info_t
    wmem_tree_t *subscriber_id_cache;
    /// Contains struct zenoh_queryable_info_t
    wmem_tree_t *queryable_id_cache;
    /// Contains struct zenoh_token_info_t
    wmem_tree_t *token_id_cache;
    wmem_tree_t *query_frame_num_cache;
};

/// A conversation between two zenoh nodes.
/// Can span over multiple network conversations (e.g. TCP, UDP, etc...).
struct zenoh_conv_data_t
{
    struct zenoh_conv_data_side_t sides[2];
};

struct net_conv_data_t
{
    const char *zids[2];
    struct zenoh_conv_data_t *zenoh_conv_data;
    bool compression_negotiated;
    uint32_t compression_start;
};

/// Return 0 or 1, an arbitrary order between the sender and the receiver in
/// net_conv_data_t.zids and zenoh_conv_data_t.sides.
uint8_t is_low_or_high(const packet_info *pinfo);

struct zenoh_conv_data_t *get_zenoh_conv_data(const packet_info *pinfo);
struct net_conv_data_t *get_net_conv_data(const packet_info *pinfo);

struct zenoh_query_info_t *zenoh_query_info_new(wmem_allocator_t *allocator);

char const *get_key_expr(const packet_info *pinfo, uint64_t scope_id, bool sender);
void register_key_expr(const packet_info *pinfo, uint64_t expr_id, const char *key_expr);
void register_zid(const packet_info *pinfo, const char *zid);

void register_subscriber(const packet_info *pinfo, uint64_t subscriber_id, const char *key_expr);
const struct zenoh_subscriber_info_t *get_subscriber(const packet_info *pinfo, uint64_t subscriber_id, bool sender);

void register_queryable(const packet_info *pinfo, uint64_t queryable_id, const char *key_expr);
const struct zenoh_queryable_info_t *get_queryable(const packet_info *pinfo, uint64_t queryable_id, bool sender);

void register_token(const packet_info *pinfo, uint64_t token_id, const char *key_expr);
const struct zenoh_token_info_t *get_token(const packet_info *pinfo, uint64_t token_id, bool sender);

/// \note assumes the sender is the one queyring
void register_query(const packet_info *pinfo, uint32_t query_id);
/// \note assumes the sender is the one replying
void register_reply(const packet_info *pinfo, uint32_t reply_id);

/// Return the queries corresponding to the query_id.
/// \note Search in the sender side if sender is true, otherwise search in the receiver side.
/// Reminder: the query data are on the query side.
/// \return a list, containst bare "uint32_t as pointers"
wmem_list_t *get_queries(const packet_info *pinfo, uint32_t query_id, bool sender);
/// Return the replies corresponding to the query_id.
/// \note Search in the sender side if sender is true, otherwise search in the receiver side.
/// Reminder: the query data are on the query side.
/// \return a list, containst bare "uint32_t as pointers"
wmem_list_t *get_replies(const packet_info *pinfo, uint32_t reply_id, bool sender);
