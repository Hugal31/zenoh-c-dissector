local zenoh_protocol = Proto("zenoh2", "Zenoh protocol")
local zenoh_utils = require("zenoh_utils")

local what_am_i_names = {
   [0] = "Router",
   [1] = "Peer",
   [2] = "Client"
}
local transport_body_type_names = {
   [0x0] = "OAM",
   [0x1] = "INIT",
   [0x2] = "OPEN",
   [0x3] = "CLOSE",
   [0x4] = "KEEP_ALIVE",
   [0x5] = "FRAME",
   [0x6] = "FRAGMENT",
   [0x7] = "JOIN",
}
local network_message_type_names = {
   [0x1F] = "OAM",
   [0x1E] = "Declare",
   [0x1D] = "Push",
   [0x1C] = "Request",
   [0x1B] = "Response",
   [0x1A] = "ResponseFinal",
   [0x19] = "Interest",
}
local msg_type_names = {
   [0x00] = "OAM",
   [0x01] = "PUT",
   [0x02] = "DEL",
   [0x03] = "QUERY",
   [0x04] = "REPLY",
   [0x05] = "ERR",
}
local ext_enc_names = {
   [0] = "Unit",
   [1] = "Z64",
   [2] = "ZBuf",
   [3] = "Reserverd",
}
local declare_body_names = {
   [0x00] = "DeclareKeyExpr",
   [0x01] = "UndeclareKeyExpr",
   [0x02] = "DeclareSubscriber",
   [0x03] = "Und",
   [0x04] = "DeclareSubscriber",
   [0x05] = "Und",
   [0x06] = "DeclareSubscriber",
   [0x07] = "Und",
   [0x1A] = "DeclareFinal",
}
local priority_names = {
   [0] = "Control",
   [1] = "RealTime",
   [2] = "InteractiveHigh",
   [3] = "InteractiveLow",
   [4] = "DataHigh",
   [5] = "Data",
   [6] = "DataLow",
   [7] = "Background",
}
local transport_body_type_field = ProtoField.uint8("zenoh2.type", "Transport body type", nil, transport_body_type_names, 0x1F)
local init_ack_field = ProtoField.bool("zenoh2.init.ack", "Is ack", 8, nil, 0x20)
local init_size_field = ProtoField.bool("zenoh2.init.size", "Size", 8, nil, 0x30)
local fragment_has_more_field = ProtoField.bool("zenoh2.fragment.has_more", "Has more", 8, nil, 0x40)
local proto_version_field = ProtoField.uint8("zenoh2.version", "Protocol version", base.DEC)
local what_am_i_field = ProtoField.uint8("zenoh2.wai", "What Am I", base.DEC, what_am_i_names, 3)
local zid_field = ProtoField.bytes("zenoh2.zid", "ZID", base.NONE)
local ext_field = ProtoField.bool("zenoh2.ext", "Extensions", 8, nil, 0x80)
local ext_id_field = ProtoField.uint8("zenoh2.ext.id", "Extension ID", base.DEC, nil, 0x0F)
local ext_enc_field = ProtoField.uint8("zenoh2.ext.enc", "Extension Encoding", base.DEC, ext_enc_names, 3 << 5)
local ext_length_field = ProtoField.uint8("zenoh2.ext.len", "Extension Length", base.DEC)
local ext_value_field = ProtoField.uint64("zenoh2.ext.value", "Ext Value", base.DEC)
local frame_reliable_field = ProtoField.bool("zenoh2.frame.reliable", "Reliable", 8, nil, 0x20)
local frame_seq_num_field = ProtoField.uint32("zenoh2.frame.seq_num", "SN", base.DEC)
local network_message_type_field = ProtoField.uint8("zenoh2.network.type", "Network message type", base.HEX, network_message_type_names, 0x1F)
local msg_type_field = ProtoField.uint8("zenoh2.msg.type", "Message type", base.HEX, msg_type_names, 0x1F)
local expr_id_field = ProtoField.uint16("zenoh2.expr_id", "Id", base.DEC)
local key_scope_field = ProtoField.uint16("zenoh2.key_scope", "Key scope", base.DEC)
local key_suffix_field = ProtoField.string("zenoh2.key_suffix", "Key suffix", base.ASCII)

local timestamp_field = ProtoField.uint64("zenoh2.msg.timestamp", "Timestamp", base.DEC)
local timestamp_hlc_id_field = ProtoField.bytes("zenoh2.msg.timestamp.id", "Timestamp HLC Id", base.NONE)
local key_expr_field = ProtoField.string("zenoh2.key_expr", "Key Expression", base.ASCII)
local payload_field = ProtoField.bytes("zenoh2.push.put.payload", "Payload", base.NONE)
local encoding_id_field = ProtoField.uint8("zenohd2.encoding.id", "Encoding ID", base.DEC, nil, 0xFE)
local encoding_schema_field = ProtoField.string("zenohd2.encoding.schema", "Encoding Schema", base.ASCII)

local interest_id_field = ProtoField.uint32("zenoh2.interest.id", "Interest ID")
local declare_type_field = ProtoField.uint8("zenoh2.declare.type", "Declare type", base.HEX, declare_body_names, 0x1F)

local net_oam_enc_field = ProtoField.uint8("zenoh2.net.oam.encoding", "Encoding", base.HEX, ext_enc_names, 0x60)
local net_oam_id_field = ProtoField.uint16("zenoh2.net.oam.id", "OAM ID")
local net_oam_value_field = ProtoField.bytes("zenoh2.net.oam.value", "OAM Value", base.NONE)

local request_id_field = ProtoField.uint32("zenoh2.request.id", "Request ID")
local query_consolidation_field = ProtoField.uint8("zenoh2.query.consolidation", "Consolidation", nil, {
   [0] = "Auto",
   [1] = "None",
   [2] = "Monotonic",
   [3] = "Latest",
})
local query_parameters_field = ProtoField.bytes("zenoh2.query.parameters", "Query parameters")
local response_request_id_field = ProtoField.uint32("zenoh2.response.id", "Response request ID")

local ext_qos_priority_field = ProtoField.uint8("zenoh2.qos.priority", "Priority", base.DEC, priority_names, 0x7)
local ext_qos_congestion_field = ProtoField.bool("zenoh2.qos.blocking", "Blocking", 8, nil, 0x8)
local ext_qos_express_field = ProtoField.bool("zenoh2.qos.express", "Express", 8, nil, 0x10)

local ip_proto = Field.new("ip.proto")

local old_zenoh_dissector = nil

zenoh_protocol.fields = {
   transport_body_type_field,
   init_ack_field,
   init_size_field,
   fragment_has_more_field,
   proto_version_field,
   what_am_i_field,
   zid_field,
   ext_field,
   ext_id_field,
   ext_enc_field,
   ext_length_field,
   frame_reliable_field,
   frame_seq_num_field,
   ext_value_field,
   network_message_type_field,
   expr_id_field,
   key_scope_field,
   key_suffix_field,
   timestamp_field,
   timestamp_hlc_id_field,
   msg_type_field,
   key_expr_field,
   payload_field,
   encoding_id_field,
   encoding_schema_field,
   interest_id_field,
   declare_type_field,
   net_oam_enc_field,
   net_oam_id_field,
   net_oam_value_field,
   request_id_field,
   query_consolidation_field,
   query_parameters_field,
   response_request_id_field,
   ext_qos_priority_field,
   ext_qos_congestion_field,
   ext_qos_express_field,
}

local transport_conversations = {}
local zenoh_conversations = {}

--- Return {uint, offset}
local VLE_MAX_LEN = 9
local function read_zint(buffer)
   local offset = 0
   local value = 0
   local i = 0

   local b = buffer(offset, 1):uint()
   while (b & 0x80) ~= 0 and i ~= 7 * (VLE_MAX_LEN - 1) do
      value = value | (b & 0x7f) << i
      offset = offset + 1
      b = buffer(offset, 1):uint()
      i = i + 7
   end

   value = value | (b << i)

   return {value, offset + 1}
end

local function dissect_zint(tree, field, buffer)
   local ret = read_zint(buffer)
   local sub_buf = buffer(0, math.min(8, ret[2]))
   ret[3] = tree:add(field, sub_buf, ret[1])
   return ret
end

local function get_net_conv_data(pinfo)
   --[[local conv = Conversation.find_from_pinfo(pinfo, true)
   if conv[zenoh_protocol] == nil then
      conv[zenoh_protocol] = {
         key_exprs_cache = {
            [pinfo.src_port] = {},
            [pinfo.dst_port] = {}
         }
      }
      end
      return conv[zenoh_protocol]--]]
   local addr_sorted
   local net_src = tostring(pinfo.net_src)
   local net_dst = tostring(pinfo.net_dst)
   if pinfo.src_port < pinfo.dst_port or (pinfo.src_port == pinfo.dst_port and net_src < net_dst) then
      addr_sorted = {{net_src, pinfo.src_port}, {net_dst, pinfo.dst_port}}
   else
      addr_sorted = {{net_dst, pinfo.dst_port}, {net_src, pinfo.src_port}}
   end
   local ret = transport_conversations[addr_sorted[1][1]]
   if ret == nil then
      ret = {}
      transport_conversations[addr_sorted[1][1]] = {
         [addr_sorted[2][1]] = {
            [addr_sorted[1][2]] = {
               [addr_sorted[2][2]] = ret
            }
         }
      }
      return ret
   end
   local ret2 = ret[addr_sorted[2][1]]
   if ret2 == nil then
      ret2 = {}
      ret[addr_sorted[2][1]] = {
         [addr_sorted[1][2]] = {
            [addr_sorted[2][2]] = ret2
         }
      }
      return ret2
   end
   local ret3 = ret2[addr_sorted[1][2]]
   if ret3 == nil then
      ret3 = {}
      ret2[addr_sorted[1][2]] = {
         [addr_sorted[2][2]] = ret3
      }
      return ret3
   end
   local ret4 = ret3[addr_sorted[2][2]]
   if ret4 == nil then
      ret4 = {}
      ret3[addr_sorted[2][2]] = ret4
   end
   return ret4
end

local function get_conv_data(pinfo)
   return get_net_conv_data(pinfo)
end

local function get_key_exprs_cache(pinfo, sender_mapping)
   local conv = get_conv_data(pinfo)
   local zid_sender = conv[tostring(pinfo.net_src)] and conv[tostring(pinfo.net_src)][pinfo.src_port]
   local zid_receiver = conv[tostring(pinfo.net_dst)] and conv[tostring(pinfo.net_dst)][pinfo.dst_port]
   if zid_sender == nil or zid_receiver == nil then
      return nil
   end
   local zid_master
   local zid_second
   if sender_mapping then
      zid_master = zid_sender
      zid_second = zid_receiver
   else
      zid_master = zid_receiver
      zid_second = zid_sender
   end

   if zenoh_conversations[zid_master] == nil then zenoh_conversations[zid_master] = {} end
   if zenoh_conversations[zid_master][zid_second] == nil then zenoh_conversations[zid_master][zid_second] = {} end

   return zenoh_conversations[zid_master][zid_second]
end

local function get_key_expr_cache(scope, pinfo, sender_mapping)
   local cache = get_key_exprs_cache(pinfo, sender_mapping)
   return cache and cache[scope]
end

local function dissect_keyexpr(buffer, pinfo, tree, has_suffix, sender_mapping, field)
   -- Expect a z16 key_scope, and optionally the suffix
   -- return {fully_resolved_key_expr, offset}
   local key_scope_res = read_zint(buffer(0))
   local key_scope = key_scope_res[1]

   local offset = key_scope_res[2]

   local suffix = ""
   local suffix_offset = 0
   local suffix_len = 0
   if has_suffix then
      local res = read_zint(buffer(offset, 2))
      suffix_len = res[1]
      offset = offset + res[2]
      suffix_offset = offset
      suffix = buffer(offset, suffix_len):string()
      offset = offset + suffix_len
   end

   local key_expr = suffix
   if key_scope ~= 0 then
      local resolved_scope = get_key_expr_cache(key_scope, pinfo, sender_mapping)
      key_expr = (resolved_scope or "??/") .. suffix
      if pinfo.number == 56 and not resolved_scope then
         print(string.format("Could not resolve scope %d (%s). src_port: %d, dst_port: %d", key_scope, sender_mapping, pinfo.src_port, pinfo.dst_port))
         zenoh_utils.tprint(get_conv_data(pinfo))
         zenoh_utils.tprint(zenoh_conversations)
      end
   end

   local label = string.format("WireExpr \"%s\" (%d, %s)", key_expr, key_scope, mapping and "sender" or "receiver")
   if field ~= nil then
      key_subtree = tree:add(field, buffer(0, offset), key_expr, label)
   else
      key_subtree = tree:add(buffer(0, offset), label)
   end
   key_subtree:add_le(key_scope_field, buffer(0, key_scope_res[2]), key_scope_res[1])
   if suffix_len > 0 then
      key_subtree:add(key_suffix_field, buffer(suffix_offset, suffix_len))
   end

   return {key_expr, offset}
end

local function zenoh_protocol_read_encoding(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_schema = (first_byte & 1) ~= 0
   local schema_len = 0
   if has_schema then
      schema_len = read_zint()
   end
   local schema_id = first_byte >> 1
   local subtree = tree:add(buffer(0, 1 + schema_len), string.format("Encoding %d", schema_id))
   subtree:add(encoding_id_field, buffer(0, 1))
   if schema_len ~= 0 then
      subtree:add(encoding_schema_field, buffer(1, schema_len))
   end
   return 1 + schema_len
end

local function dissect_qos_type(buffer, pinfo, tree)
   local byte
   if buffer:len() == 1 then
      byte = buffer:uint()
   else
      data = read_zint(buffer)[1]
   end
   local priority = byte & 0x07
   local blocking = byte & 0x08 ~=0
   local express = byte & 0x10 ~= 0
   local priority_name = priority_names[priority] or tostring(priority)
   local congestion_name = blocking and "Block" or "Drop"
   tree:add(ext_qos_priority_field, buffer)
   tree:add(ext_qos_congestion_field, buffer)
   tree:add(ext_qos_express_field, buffer)
   tree:set_text(string.format("QoS { priority: %s, congestion: %s, express: %s }", priority_name, congestion_name, express))
end

local function zenoh_protocol_read_ext(buffer, pinfo, tree, dissectors)
   local first_byte = buffer(0, 1)
   local first_byte_value = first_byte:uint()
   local id = first_byte_value & 0xF
   local enc = (first_byte_value & (3 << 5)) >> 5
   local has_more = (first_byte_value & (1 << 7)) ~= 0
   local length_or_value = 0
   local offset = 1
   if enc == 1 or enc == 2 then
      local ret = read_zint(buffer(1))
      length_or_value = ret[1]
      offset = offset + ret[2]
   end
   local length = 0
   if enc == 2 then
      length = length_or_value
   end

   local subtree = tree:add(buffer(0, offset + length), string.format("Ext (%x)", id))
   subtree:add(ext_enc_field, first_byte)
   if enc == 0 then
      if dissectors and dissectors[id] ~= nil then
         dissectors[id](buffer(0, 0), pinfo, subtree)
      end
      return {1, has_more}
   elseif enc == 1 then
      local zint_buf = buffer(1, math.min(8, offset - 1))
      if dissectors and dissectors[id] ~= nil then
         dissectors[id](zint_buf, pinfo, subtree)
      elseif id == 1 then
         dissect_qos_type(zint_buf, pinfo, subtree)
      else
         subtree:add_le(ext_value_field, zint_buf)
      end
      return {offset, has_more}
   elseif enc == 2 then
      local data = buffer(offset, length)
      subtree:add(data, "Data")
      if dissectors and dissectors[id] ~= nil then
         dissectors[id](data, pinfo, subtree)
      end
      return {2 + length, has_more}
   else
      return {2, has_more}
   end
end

local function zenoh_protocol_read_exts(buffer, pinfo, tree, dissectors)
   local offset = 0
   local has_more = true
   while has_more do
      local ret = zenoh_protocol_read_ext(buffer(offset), pinfo, tree, dissectors)
      offset = offset + ret[1]
      has_more = ret[2]
   end
   return offset
end

local function dissect_rmw_zenoh_attachment(buffer, pinfo, tree)
   local offset = 0
   while offset < buffer:len() do
      local ret = read_zint(buffer(offset))
      local str_start = offset + ret[2]
      local str_len = ret[1]
      offset = offset + ret[2] + str_len
      if offset + 8 >= buffer:len() then
         break
      end
      local value
      local key = buffer(str_start, str_len):string()
      if key == "sequence_number" or key == "source_timestamp" then
         value = buffer(offset, 8):le_uint64()
         offset = offset + 8
      elseif key == "source_gid" then
         value = buffer(offset):bytes()
         offset = buffer:len()
      else
         break
      end
      tree:add(buffer(str_start, offset - str_start), string.format("%s: %s", key, value))
   end
end

local function zenoh_protocol_dissect_put(buffer, pinfo, tree)
   tree:append_text("Put")
   tree:add(msg_type_field, buffer(0, 1))
   local first_byte_value = buffer(0, 1):uint()
   local has_timestamp = (first_byte_value & 0x20) ~= 0
   local has_enc = (first_byte_value & 0x40) ~= 0
   local has_exts = (first_byte_value & 0x80) ~= 0

   local offset = 1
   if has_timestamp then
      local ret = read_zint(buffer(offset))
      local timestamp = ret[1]
      local offset_then = offset
      local tstree = tree:add("Timestamp", buffer(offset))
      tstree:add_le(timestamp_field, buffer(offset, math.min(8, ret[2])))
      offset = offset + ret[2]
      ret = read_zint(buffer(offset))
      local hlc_id_len = ret[1]
      offset = offset + ret[2]
      tstree:add_le(timestamp_hlc_id_field, buffer(offset, hlc_id_len))
      offset = offset + hlc_id_len
      tstree:set_len(offset - offset_then)

      local ts_s = math.floor(timestamp / (1 << 32))
      local ts_ns = timestamp % (1 << 32)
      tstree:append_text(string.format(": %s.%09d UTC", os.date("%c", ts_s), ts_ns))
   end

   if has_enc then
      offset = offset + zenoh_protocol_read_encoding(buffer(offset), pinfo, tree)
   end

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree, {[3] = dissect_rmw_zenoh_attachment})
   end

   local ret = read_zint(buffer(offset))
   local payload_len = ret[1]
   tree:add(buffer(offset, ret[2]), string.format("Payload len: %d", ret[1]))
   offset = offset + ret[2]
   tree:add(payload_field, buffer(offset, math.min(payload_len, buffer:len() - offset)))
   offset = offset + payload_len

   tree:set_len(offset)

   return offset
end

local function zenoh_protocol_dissect_push(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_exts = (first_byte & 0x80) ~= 0
   local has_suffix = (first_byte & (1 << 5)) ~= 0
   local mapping = (first_byte & (1 << 6)) ~= 0

   local key_expr_ret = dissect_keyexpr(buffer(1), pinfo, tree, has_suffix, mapping, key_expr_field)
   local offset = 1 + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree, {[1]=dissect_qos_type})
   end

   local body_buf = buffer(offset)
   push_body_id = body_buf(0, 1):uint() & 0x1F
   if push_body_id == 0x1 then
      local body_tree = tree:add(body_buf, "")
      offset = offset + zenoh_protocol_dissect_put(body_buf, pinfo, body_tree)
   else
      tree:add(body_buf, string.format("Unknown push type %x", push_body_id))
   end
   tree:set_len(offset)
   return offset
end

local function zenoh_protocol_dissect_declare_keyexpr(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_named = (first_byte & 0x20) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   local expr_id_ret = read_zint(buffer(offset))
   tree:add(expr_id_field, buffer(offset, expr_id_ret[2]))
   offset = offset + expr_id_ret[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, true, key_expr_field)
   offset = offset + key_expr_ret[2]

   local key_expr_cache = get_key_exprs_cache(pinfo, true)
   key_expr_cache[expr_id_ret[1]] = key_expr_ret[1]

   return offset
end

local function zenoh_protocol_dissect_declare_subscriber(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_named = (first_byte & 0x20) ~= 0
   local has_mapping = (first_byte & 0x40) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   local sub_id_ret = read_zint(buffer(offset))
   offset = offset + sub_id_ret[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, has_mapping)
   offset = offset + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end
   return offset
end

local function zenoh_protocol_dissect_declare_queryable(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_named = (first_byte & 0x20) ~= 0
   local has_mapping = (first_byte & 0x40) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   local queryable_id_ret = read_zint(buffer(offset))
   offset = offset + queryable_id_ret[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, has_mapping)
   offset = offset + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end
   return offset
end

local function zenoh_protocol_dissect_declare_token(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_named = (first_byte & 0x20) ~= 0
   local has_mapping = (first_byte & 0x40) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   local token_id_ret = read_zint(buffer(offset))
   offset = offset + token_id_ret[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, has_mapping)
   offset = offset + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end
   return offset
end

local function zenoh_protocol_dissect_declare_final(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end
   return offset
end

local function zenoh_protocol_dissect_declare(buffer, pinfo, tree)
   local first_byte = buffer(0, 1)
   local first_byte_value = first_byte:uint()
   local has_interest = (first_byte_value & 0x20) ~= 0
   local has_exts = (first_byte_value & 0x80) ~= 0

   local offset = 1
   if has_interest then
      local ret = read_zint(buffer(offset))
      tree:add_le(interest_id_field, buffer(offset, ret[2]))
      offset = offset + ret[2]
   end

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   local declare_type = buffer(offset, 1):uint() & 0x1F
   tree:set_text(declare_body_names[declare_type])
   tree:add(declare_type_field, buffer(offset, 1))
   if declare_type == 0 then
      offset = offset + zenoh_protocol_dissect_declare_keyexpr(buffer(offset), pinfo, tree)
   elseif declare_type == 0x02 then
      offset = offset + zenoh_protocol_dissect_declare_subscriber(buffer(offset), pinfo, tree)
   elseif declare_type == 0x04 then
      offset = offset + zenoh_protocol_dissect_declare_queryable(buffer(offset), pinfo, tree)
   elseif declare_type == 0x06 then
      offset = offset + zenoh_protocol_dissect_declare_token(buffer(offset), pinfo, tree)
   elseif declare_type == 0x1A then
      offset = offset + zenoh_protocol_dissect_declare_final(buffer(offset), pinfo, tree)
   else
      offset = offset + 1
   end
   tree:set_len(offset)

   return offset
end

local function zenoh_protocol_dissect_query(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_consolidation = (first_byte & 0x20) ~= 0
   local has_parameters = (first_byte & 0x40) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0

   local ret = dissect_zint(tree, query_consolidation_field, buffer(1))
   local offset = 1 + ret[2]

   if has_parameters then
      ret = read_zint(buffer(offset))
      local parameters_length = ret[1]
      offset = offset + ret[2]
      tree:add(query_parameters_field, buffer(offset, parameters_length))
      offset = offset + parameters_length
   end

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   return offset
end

local function zenoh_protocol_dissect_request(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_named = (first_byte & 0x20) ~= 0
   local has_mapping = (first_byte & 0x40) ~= 0
   local has_exts = (first_byte & 0x80) ~= 0
   local offset = 1

   local res = dissect_zint(tree, request_id_field, buffer(offset))
   local _request_id = res[1]
   offset = offset + res[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, has_mapping)
   offset = offset + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   local query_buffer = buffer(offset)
   return offset + zenoh_protocol_dissect_query(query_buffer, pinfo, tree:add(query_buffer, "Query"))
end

local function zenoh_protocol_dissect_response_final(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_exts = (first_byte & 0x80) ~= 0

   local res = dissect_zint(tree, response_request_id_field, buffer(1))
   local offset = 1 + res[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   return offset
end

local function zenoh_protocol_dissect_response(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local has_exts = (first_byte & 0x80) ~= 0
   local has_named = (first_byte & 0x20) ~= 0
   local has_mapping = (first_byte & 0x40) ~= 0

   local res = dissect_zint(tree, response_request_id_field, buffer(1))
   local offset = 1 + res[2]

   local key_expr_ret = dissect_keyexpr(buffer(offset), pinfo, tree, has_named, has_mapping)
   offset = offset + key_expr_ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   tree:add(payload_field, buffer(offset))

   return offset
end

local function zenoh_protocol_dissect_net_oam(buffer, pinfo, tree)
   local first_byte = buffer(0, 1):uint()
   local enc = (first_byte >> 5) & 3
   local has_exts = (first_byte & 0x80) ~= 0

   tree:add(net_oam_enc_field, buffer(0, 1))

   local offset = 1
   local ret = dissect_zint(tree, net_oam_id_field, buffer(offset))
   offset = offset + ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, tree)
   end

   local length = 0
   if enc == 1 or enc == 2 then
      ret = read_zint(buffer(offset))
      if enc == 2 then
         length = ret[1]
      else
         tree:add(net_oam_value_field, buffer(offset, ret[2]))
      end
      offset = offset + ret[2]
   end

   if enc == 2 and length > 0 then
      tree:add(net_oam_value_field, buffer(offset, length))
      offset = offset + length
   end

   return offset
end

local function zenoh_protocol_dissect_net_message(buffer, pinfo, tree)
   local first_byte = buffer(0, 1)
   local first_byte_value = first_byte:uint()
   local id = first_byte_value & 0x1F

   local length = buffer:len()
   local type_name = network_message_type_names[id]
   if type_name == nil then
      type_name = string.format("0x%x", id)
   end
   pinfo.cols.info:append(type_name)
   local subtree = tree:add(buffer, type_name)
   subtree:add(network_message_type_field, first_byte)
   if id == 0x1D then
      return zenoh_protocol_dissect_push(buffer, pinfo, subtree)
   elseif id == 0x1A then
      return zenoh_protocol_dissect_response_final(buffer, pinfo, subtree)
   elseif id == 0x1B then
      return zenoh_protocol_dissect_response(buffer, pinfo, subtree)
   elseif id == 0x1C then
      return zenoh_protocol_dissect_request(buffer, pinfo, subtree)
   elseif id == 0x1E then
      return zenoh_protocol_dissect_declare(buffer, pinfo, subtree)
   elseif id == 0x1F then
      return zenoh_protocol_dissect_net_oam(buffer, pinfo, subtree)
   else
      return length
   end
end

local function zenoh_protocol_dissect_frame(buffer, pinfo, tree)
   local subtree = tree:add(buffer, "Frame")
   pinfo.cols.info:append("Frame[")
   local first_byte = buffer(0, 1)
   local has_exts = (first_byte:uint() & 0x80) ~= 0
   subtree:add(frame_reliable_field, first_byte)
   subtree:add(ext_field, first_byte)

   local offset = 1
   local ret = dissect_zint(subtree, frame_seq_num_field, buffer(offset))
   offset = offset + ret[2]

   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, subtree)
   end

   while offset < buffer:len() do
      offset = offset + zenoh_protocol_dissect_net_message(buffer(offset), pinfo, subtree)
      if offset < buffer:len() then
         pinfo.cols.info:append(", ")
      end
   end

   pinfo.cols.info:append("]")

   return true
end

local function zenoh_protocol_dissect_init(buffer, pinfo, tree)
   local first_byte = buffer(0, 1)
   local is_ack = (first_byte:uint()) & 0x20 ~= 0
   local subtree = tree:add(is_ack and "InitAck" or "InitSyn")
   pinfo.cols.info:append((is_ack and "InitAck" or "InitSyn") .. ",")
   subtree:add(init_ack_field, first_byte)

   subtree:add(init_size_field, first_byte)
   subtree:add(ext_field, first_byte)
   subtree:add(proto_version_field, buffer(1, 1))

   local third_byte = buffer(2, 1)
   subtree:add(what_am_i_field, third_byte)
   local zid_len = 1 + (third_byte:uint() >> 4)
   local zid_buf = buffer(3, zid_len)
   local zid_tree = subtree:add_le(zid_field, zid_buf)
   local zid_string = zenoh_utils.zid_to_string(zid_buf)
   zid_tree:set_text("ZID: " .. zid_string)

   local net_conv_data = get_net_conv_data(pinfo)
   local net_src = tostring(pinfo.net_src)
   if net_conv_data[net_src] == nil then
      net_conv_data[net_src] = {}
   end
   net_conv_data[net_src][pinfo.src_port] = zid_string
   -- print(string.format("Register %s:%s -> %s:%s to be %s", net_src, pinfo.src_port, pinfo.net_dst, pinfo.dst_port, zid_string))

   return offset
end

local function zenoh_protocol_dissect_fragment(buffer, pinfo, tree)
   pinfo.cols.info:append("Fragment")

   local subtree = tree:add(buffer, "Fragment")

   local header = buffer(0, 1)
   subtree:add(fragment_has_more_field, header)
   subtree:add(frame_reliable_field, header)
   local has_exts = header:uint() & 0x80 ~= 0

   local offset = 1
   local ret = dissect_zint(subtree, frame_seq_num_field, buffer(offset))
   offset = offset + ret[2]

   is_first_fragment = False
   if has_exts then
      offset = offset + zenoh_protocol_read_exts(buffer(offset), pinfo, subtree, {
                                                    [2] = function (a, b, tree) is_first_fragment = true ; tree:set_text("First Fragment") end
                                                })
   end

   if is_first_fragment then
      pinfo.cols.info:append('[')
      zenoh_protocol_dissect_net_message(buffer(offset), pinfo, subtree)
      pinfo.cols.info:append(']')
   end
end

local function zenoh_protocol_dissect_message(buffer, pinfo, tree)
   local subtree = tree:add(zenoh_protocol, buffer)

   subtree:add(transport_body_type_field, buffer(0, 1))

   local message_type = buffer(0, 1):uint() & 0x1F
   if message_type == 0x1 then
      return zenoh_protocol_dissect_init(buffer, pinfo, subtree)
   elseif message_type == 0x5 then
      return zenoh_protocol_dissect_frame(buffer, pinfo, subtree)
   elseif message_type == 0x6 then
      return zenoh_protocol_dissect_fragment(buffer, pinfo, subtree)
   else
      pinfo.cols.info:append(transport_body_type_names[message_type])
      return true
   end
   return true
end

local function zenoh_protocol_get_header_length(buffer, pinfo, offset)
   local msg_length = buffer(offset, 2):le_uint()
   local first_byte = buffer(2, 1):uint()
   local has_more = (first_byte & 0x40) ~= 0
   local offset = 2 + msg_length
   --[[while (first_byte & 0x1F) == 0x6 and has_more and offset < buffer:len() do
      -- This is never used...
      print("In the length loop !", offset, pinfo.number)
      msg_length = buffer(offset, 2):le_uint()
      first_byte = buffer(2 + offset, 1):uint()
      has_more = (first_byte & 0x40) ~= 0
      offset = offset + 2 + msg_length
      end-]]
   return offset
end

local function zenoh_protocol_dissect_packet(buffer, pinfo, tree)
   if ip_proto()() == 6 then
      --[[local offset = 2
      local first_byte = buffer(offset, 1):uint()
      local has_more = (first_byte & 0x40) ~= 0
      while (first_byte & 0x1F) == 0x6 and has_more and offset < buffer:len() do
         -- This is never used...
         print("In the loop !", offset, pinfo.number)
         local msg_length = buffer(offset, 2):le_uint()
         first_byte = buffer(2 + offset, 1):uint()
         has_more = (first_byte & 0x40) ~= 0
         offset = offset + 2 + msg_length
      end
      print("End of the loop", pinfo.number, offset, first_byte, has_more)
      if (first_byte & 0x1F) == 0x6 and has_more then
         print("Ask for a bigger read of ", offset + 3)
         return dissect_tcp_pdus(buffer, tree, offset + 3, zenoh_protocol_get_header_length, zenoh_protocol_dissect_packet)
      end-]]
      buffer = buffer(2)
   end
   local old_info = pinfo.cols.info
   if pinfo.cols.protocol ~= "Zenoh" then
      pinfo.cols.protocol = "Zenoh"
      pinfo.cols.info = string.format("%u -> %u ", pinfo.src_port, pinfo.dst_port)
   end
   if zenoh_protocol_dissect_message(buffer, pinfo, tree) ~= false then
      return true
   end
   pinfo.cols.info:set_text(old_info)
   return false
end

function zenoh_protocol.dissector(buffer, pinfo, tree)
   local proto = ip_proto()()
   if proto == 6 then
      return dissect_tcp_pdus(buffer, tree, 3, zenoh_protocol_get_header_length, zenoh_protocol_dissect_packet)
   else
      return zenoh_protocol_dissect_packet(buffer, pinfo, tree)
   end
end

local tcp_port = DissectorTable.get("tcp.port")
old_zenoh_dissector = tcp_port:get_dissector(7447)
tcp_port:add(7447, zenoh_protocol)
tcp_port:add(7448, zenoh_protocol)
-- TODO REMOVE
tcp_port:add(42252, zenoh_protocol)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(7447, zenoh_protocol)
-- TODO REMOVE
udp_port:add(34160, zenoh_protocol)

-- zenoh_protocol:register_heuristic("udp", zenoh_scouting_heuristic)
