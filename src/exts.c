#include "exts.h"

#include <epan/packet.h>

#include "fields.h"
#include "utils.h"

static struct ext_dissector_table_entry *try_get_dissector_entry(ext_dissector_table_t dissector_table, uint8_t id)
{
    while (dissector_table->id != 0 && dissector_table->id != id)
        ++dissector_table;
    return dissector_table;
}

static int dissect_ext(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       int offset,
                       ext_dissector_table_t dissector_table,
                       void *data,
                       bool *has_more)
{
    const uint8_t header = tvb_get_uint8(tvb, offset);
    const uint8_t id = header & 0xF;
    // const uint8_t mandatory = header & 0x10;
    const uint8_t enc = (header >> 5) & 0b11;
    *has_more = (header & 0x80) != 0;

    offset += 1;
    int start = offset;

    switch (enc)
    {
        default:
        case 0b00: start = offset - 1; break;
        case 0b01:
        {
            read_zint(tvb, &offset);
            break;
        }
        case 0b10:
        {
            const int length = (int)read_zint(tvb, &offset);
            start = offset;
            offset += length;
            break;
        }
    }
    const int length = offset - start;

    const struct ext_dissector_table_entry *dissector_entry =
            dissector_table ? try_get_dissector_entry(dissector_table, id) : NULL;
    const char *const dissector_name = dissector_entry ? dissector_entry->name : NULL;
    if (dissector_entry && dissector_entry->dissector)
    {
        dissector_entry->dissector(tvb, pinfo, tree, start, length, data);
    }
    else
    {
        if (enc == 0)
        {
            proto_item *item = proto_tree_add_item(tree, hf_ext_unit, tvb, start, length, ENC_NA);
            if (dissector_name)
                proto_item_set_text(item, "%s", dissector_name);
            else
                proto_item_set_text(item, "Unit Ext (%u)", id);
        }
        else if (enc == 1)
        {
            proto_item *item;
            uint64_t value;
            dissect_zint(tvb, tree, start, hf_ext_z64, &item, &value);
            if (dissector_name)
                proto_item_set_text(item, "%s: %lu", dissector_name, value);
            else
                proto_item_set_text(item, "Z64 Ext (%u): %lu", id, value);
        }
        else
        {
            char *display;
            proto_item *item = proto_tree_add_item_ret_display_string(
                    tree, hf_ext_zbuf, tvb, start, length, ENC_NA, pinfo->pool, &display);
            if (display)
                proto_item_set_text(item, "%s: %s", dissector_name ? dissector_name : "ZBuf Ext", display);
            wmem_free(pinfo->pool, display);
        }
    }

    return offset;
}

int dissect_exts(tvbuff_t *tvb,
                 packet_info *pinfo,
                 proto_tree *tree,
                 int offset,
                 ext_dissector_table_t dissector_table,
                 void *data)
{
    bool has_more = true;
    while (has_more)
    {
        offset = dissect_ext(tvb, pinfo, tree, offset, dissector_table, data, &has_more);
    }
    return offset;
}

#define priority_names_VALUE_STRING_LIST(V) \
    V(ZENOH_PRIORITY_CONTROL, 0, "Control") \
    V(ZENOH_PRIORITY_REALTIME, 1, "RealTime") \
    V(ZENOH_PRIORITY_INTERACTIVE_HIGH, 2, "InteractiveHigh") \
    V(ZENOH_PRIORITY_INTERACTIVE_LOW, 3, "InteractiveLow") \
    V(ZENOH_PRIORITY_DATA_HIGH, 4, "DataHigh") \
    V(ZENOH_PRIORITY_DATA, 5, "Data") \
    V(ZENOH_PRIORITY_DATA_LOW, 6, "DataLow") \
    V(ZENOH_PRIORITY_BACKGROUND, 7, "Background")

VALUE_STRING_ARRAY(priority_names);

void dissect_qos_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int length, void *data _U_)
{
    const int start = offset;
    uint64_t value = length ? read_zint(tvb, &offset) : 0;
    proto_item *item;
    proto_tree_add_subtree(tree, tvb, start, length, ett_zenoh, &item, "QoSExt { ");

    if (value == 0)
    {
        proto_item_append_text(item, "NoQoS");
    }
    else if (value == 1)
    {
        proto_item_append_text(item, "priorities: None, reliability: None ");
    }
    else
    {
        uint8_t tag = value & 0b111;
        proto_item_append_text(item, "priorities: ");
        if (tag & 0b10)
        {
            uint8_t priorities_start = (value >> 3) & 0xFF;
            uint8_t priorities_end = (value >> (3 + 8)) & 0xFF;
            const char *start_name = try_val_to_str(priorities_start, priority_names);
            const char *end_name = try_val_to_str(priorities_end, priority_names);
            if (start_name)
                proto_item_append_text(item, "%s-", start_name);
            else
                proto_item_append_text(item, "%u-", priorities_start);
            if (end_name)
                proto_item_append_text(item, "%s, reliability: ", end_name);
            else
                proto_item_append_text(item, "%u, reliability: ", priorities_end);
        }
        else
        {
            proto_item_append_text(item, "None, reliability: ");
        }

        if (tag & 0b100)
        {
            bool is_reliable = (value >> (3 + 8 + 8)) & 1;
            proto_item_append_text(item, is_reliable ? "Reliable" : "BestEffort");
        }
        else
        {
            proto_item_append_text(item, "None");
        }
    }
    proto_item_append_text(item, " }");
}

void dissect_qos_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int length, void *data _U_)
{
    const int start = offset;
    uint64_t value = read_zint(tvb, &offset);

    uint8_t priority = value & 0b00111;
    bool blocking = (value & 0b01000) != 0;
    bool express = (value & 0b10000) != 0;

    proto_item *item;
    proto_tree_add_subtree(tree, tvb, start, length, ett_zenoh, &item, "QoS { priority: ");

    const char *priority_name = try_val_to_str(priority, priority_names);
    if (priority_name)
        proto_item_append_text(item, "%s", priority_name);
    else
        proto_item_append_text(item, "%u", priority);

    proto_item_append_text(
            item, ", congestion: %s, express: %s }", blocking ? "Block" : "Drop", express ? "True" : "False");
}

struct ext_dissector_table_entry default_ext_dissector_table[2] = {
        {1, "QosType", dissect_qos_type},
        {0, NULL, NULL},
};
