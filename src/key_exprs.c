#include "key_exprs.h"

#include "conv.h"
#include "fields.h"
#include "utils.h"

int dissect_key_expr(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     int offset,
                     bool has_suffix,
                     bool mapping,
                     const char **ret)
{
    proto_item *item = proto_tree_add_item(tree, hf_key_expr, tvb, offset, 0, ENC_ASCII);
    proto_tree *subtree = proto_item_add_subtree(item, ett_zenoh);

    uint64_t scope;
    offset = dissect_zint(tvb, subtree, offset, hf_key_expr_scope, NULL, &scope);

    const uint8_t *suffix_u8 = NULL;
    if (has_suffix)
    {
        int suffix_len = (int)read_zint(tvb, &offset);
        proto_tree_add_item_ret_string(
                subtree, hf_key_expr_suffix, tvb, offset, suffix_len, ENC_ASCII, pinfo->pool, &suffix_u8);
        offset += suffix_len;
    }
    const char *suffix = (const char *)suffix_u8;

    wmem_allocator_t *allocator = pinfo->pool;
    char const *res = NULL;
    bool do_free = false;
    if (scope == 0)
    {
        res = wmem_strdup(allocator, suffix);
        do_free = true;
    }
    else
    {
        char const *prefix = get_key_expr(pinfo, scope, mapping);
        if (!prefix)
            prefix = "??";
        if (suffix)
        {
            const size_t len = strlen(prefix) + 1 + strlen(suffix) + 1;
            char *buf = wmem_alloc(allocator, len);
            do_free = true;
            if (suffix[0] == '/')
                snprintf(buf, len, "%s%s", prefix, suffix);
            else
                snprintf(buf, len, "%s/%s", prefix, suffix);
            res = buf;
        }
        else
        {
            res = prefix;
        }
    }

    if (res)
    {
        proto_item_append_text(item, "%s", res);
        if (scope != 0)
            proto_item_set_generated(item);
        if (item && fvalue_type_ftenum(item->finfo->value) == FT_STRING)
            fvalue_set_string(item->finfo->value, res);
        if (ret)
        {
            *ret = res;
        }
        else if (do_free)
        {
            wmem_free(allocator, (char *)res);
        }
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}
