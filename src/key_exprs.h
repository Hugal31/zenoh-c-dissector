#pragma once

#include <epan/packet.h>

/**
 *
 * @param tvb
 * @param pinfo
 * @param tree
 * @param offset
 * @param has_suffix
 * @param mapping
 * @param ret[out] If not NULL, will set the guessed key expr.
 *                 The caller should not deallocate the value. It's lifetime is at min the one of the pinfo-pool.
 * @return
 */
int dissect_key_expr(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     int offset,
                     bool has_suffix,
                     bool mapping,
                     const char **ret);