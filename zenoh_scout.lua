local MESSAGE_TYPE_SCOUT = 0x1
local MESSAGE_TYPE_HELLO = 0x2

local scout_interests_value_strings = {
   [0] = "No one",
   [1] = "Routers",
   [2] = "Peer",
   [3] = "Routers&peers",
   [4] = "Clients",
   [5] = "Routers&clients",
   [6] = "Peers&clients",
   [7] = "Routers&peers&clients",
}

local hello_what_value_strings = {
   [0x0] = "Router",
   [0x1] = "Peer",
   [0x10] = "Client",
}

local zenoh_scouting_protocol = Proto("zenoh_scouting", "Zenoh Scouting protocol")
local message_type_field = ProtoField.uint8("zenoh_scouting.type",
                                            "Scouting message type",
                                            nil,
                                            {[MESSAGE_TYPE_SCOUT] = "Scout", [MESSAGE_TYPE_HELLO] = "Hello"},
                                            0x1F)
local extensions_field = ProtoField.bool("zenoh_scouting.extensions",
                                         "Extensions",
                                         base.DEC,
                                         nil,
                                         0x80)
local has_locators_field = ProtoField.bool("zenoh_scouting.has_locators", "Has locators", base.HEX, nil, 0x20)
local version_field = ProtoField.uint8("zenoh_scouting.version", "Version")
local scout_interests_field = ProtoField.uint8("zenoh_scouting.scout.interests", "Interests", base.HEX, scout_what_value_strings, 0x7)
local hello_what_field = ProtoField.uint8("zenoh_scouting.hellow.what", "What", base.HEX, hello_what_value_strings, 0x3)
local zid_length_field = ProtoField.uint8("zenoh_scouting.zid_length", "ZID length", base.DEC, nil, 0xF0)
local zid_flag_field = ProtoField.bool("zenoh_scouting.zid_flag", "Has ZID", base.HEX, nil, 0x8)
local zid_field = ProtoField.bytes("zenoh_scouting.zid", "ZID")
local locator_field = ProtoField.string("zenoh_scouting.locator", "Locator", base.UNICODE)

zenoh_scouting_protocol.fields = {
   message_type_field,
   extensions_field,
   version_field,
   scout_interests_field,
   hello_what_field,
   zid_flag_field,
   zid_length_field,
   zid_field,
   has_locators_field,
   locator_field,
}

local used_ports = {}

local zenoh_utils = require("zenoh_utils")
local zid_to_string = zenoh_utils.zid_to_string

function zenoh_scouting_protocol.dissector(buffer, pinfo, tree)
   local length = buffer:len()
   if length < 3 then
      return false
   end

   pinfo.cols.protocol = "Zenoh Scout"
   local summary = ""

   local subtree = tree:add(zenoh_scouting_protocol, buffer(), "Zenoh scouting protocol")
   local first_byte = buffer(0, 1)
   local message_type = first_byte:uint() & message_type_field.mask
   subtree:add(message_type_field, first_byte)
   subtree:add(extensions_field, first_byte)
   subtree:add(version_field, buffer(1, 1))

   used_ports[pinfo.src_port] = true

   local has_locators = false
   if message_type == MESSAGE_TYPE_HELLO then
      subtree:add(has_locators_field, first_byte)
      has_locators = (first_byte:uint() & 0x20) ~= 0
   end

   local third_byte = buffer(2, 1)
   local has_zid = false
   if message_type == MESSAGE_TYPE_SCOUT then
      subtree:add(scout_interests_field, third_byte)
      subtree:add(zid_flag_field, third_byte)
      has_zid = (third_byte:uint() & 0x8) ~= 0
      summary = "Scout for " .. scout_interests_value_strings[third_byte:uint() & 0x7]
   elseif message_type == MESSAGE_TYPE_HELLO then
      subtree:add(hello_what_field, third_byte)
      has_zid = true
      summary = hello_what_value_strings[third_byte:uint() & 0x5] .. " -> Hello"
   end
   local zid_length = 0
   if has_zid then
      zid_length = 1 + (third_byte:uint() >> 4)
      subtree:add(zid_length_field, third_byte)
   end

   if zid_length > 0 then
      local zid_range = buffer(3, zid_length)
      subtree:add(zid_field, zid_range, zid_range:string(ENC_STR_HEX), "ZID: " .. zid_to_string(zid_range))
   end

   -- Locators
   -- local locators_subtree = subtree:add()
   -- 1 + for number of locators
   local offset = 1 + 3 + zid_length
   while has_locators and buffer:reported_len() > offset + 1 do
      local locator_length = buffer(offset, 1):uint()
      subtree:add(locator_field, buffer(offset + 1, locator_length))
      offset = offset + 1 + locator_length
   end

   if summary ~= "" then
      pinfo.cols.info:append(" " .. summary)
   end

   return true
end

local function zenoh_scouting_heuristic(buffer, pinfo, tree)
   if not used_ports[pinfo.dst_port] then
      return false
   end

   return zenoh_scouting_protocol.dissector(buffer, pinfo, tree)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(7446, zenoh_scouting_protocol)

zenoh_scouting_protocol:register_heuristic("udp", zenoh_scouting_heuristic)
