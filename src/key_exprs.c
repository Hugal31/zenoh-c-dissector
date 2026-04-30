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
    const int start_offset = offset;

    /* Use a placeholder item first so we can attach a subtree for the sub-fields.
     * We replace it with a proper proto_tree_add_string() after res is computed. */
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
        res = suffix ? wmem_strdup(allocator, suffix) : "";
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

    /* Update the placeholder item: set the length and the resolved string value.
     * Avoid fvalue_set_string() on a live proto_item — it corrupts WS's internal
     * wmem bookkeeping on subsequent packets.  Use proto_item_set_text() for the
     * display label and let the correct TVB-backed fvalue stay untouched. */
    proto_item_set_len(item, offset - start_offset);
    if (scope != 0)
        proto_item_set_generated(item);
    if (res)
        proto_item_set_text(item, "Key Expr: %s", res);

    if (ret)
    {
        *ret = res;
    }
    else if (do_free && res && res[0] != '\0')
    {
        wmem_free(allocator, (char *)res);
    }

    return offset;
}
