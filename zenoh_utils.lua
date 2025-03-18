local zenoh_utils = {}

function zenoh_utils.zid_to_string(buffer)
   local blen = buffer:len()
   local res = ""
   for i=(blen - 1),0,-1 do
      res = res .. string.format("%x", buffer(i, 1):uint())
   end
   return res
end

local function tprint(tbl, indent)
   if not indent then indent = 0 end
   for k, v in pairs(tbl) do
      formatting = string.rep("  ", indent) .. string.format("%s:", k)
      if type(v) == "table" then
         print(formatting)
         tprint(v, indent+1)
      else
         print(formatting .. v)
      end
   end
end

zenoh_utils.tprint = tprint

return zenoh_utils
