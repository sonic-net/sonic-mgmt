-- KEYS[1] - vlan id pool set key
-- KEYS[2] - port vlan list key
-- ARGV[1:] - assigned vlan ids

local used_vlanidpool = KEYS[1]
local vlan_list_name = KEYS[2]

local _old_vlanids = redis.call('SMEMBERS', vlan_list_name)
local old_vlanids = {}
for i, v in ipairs(_old_vlanids) do
    old_vlanids[v] = true
end

local new_vlanids = {}
for i = 1, #ARGV, 1 do
    table.insert(new_vlanids, ARGV[i])
    if old_vlanids[ARGV[i]] then
        old_vlanids[ARGV[i]] = nil
    end
end

local free_vlanids = {}
for k, _ in pairs(old_vlanids) do
    table.insert(free_vlanids, k)
end

redis.call('DEL', vlan_list_name)

if next(new_vlanids) ~= nil then
    redis.call('SADD', vlan_list_name, unpack(new_vlanids))
    redis.call('SADD', used_vlanidpool, unpack(new_vlanids))
end

if next(free_vlanids) ~= nil then
    redis.call('SREM', used_vlanidpool, unpack(free_vlanids))
end
