-- this lua script is used in qosconfig test
-- it automates walking thru WRED objects in the ASIC DB
-- to check whether any of objects holds a record with
-- red min threshold equal to given value

local keys = redis.call("KEYS", "ASIC_STATE:SAI_OBJECT_TYPE_WRED*")
local res=""
for i, key in ipairs(keys) do
  local val = redis.call("HGET", key, "SAI_WRED_ATTR_RED_MIN_THRESHOLD")
  if val == ARGV[1] then
    res = val
  end
end
return res

