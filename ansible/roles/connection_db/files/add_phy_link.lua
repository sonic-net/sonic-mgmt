-- KEYS[1] - start device port list key
-- KEYS[2] - start device port table key
-- KEYS[3] - end device port list key
-- KEYS[4] - end device port table key
-- ARGV[1] - start device
-- ARGV[2] - start port
-- ARGV[3] - end device
-- ARGV[4] - end port
-- ARGV[5] - band width
-- ARGV[6] - vlan mode

local start_device = ARGV[1]
local start_port = ARGV[2]
local end_device = ARGV[3]
local end_port = ARGV[4]
local bandwidth = ARGV[5]
local vlan_mode = ARGV[6] 
local endport0 = start_device .. ':' .. start_port
local endport1 = end_device .. ':' .. end_port

local link_detail = string.format('%s:%s <--%s, %s--> %s:%s', start_device, start_port, vlan_mode, bandwidth, end_device, end_port)

redis.log(redis.LOG_NOTICE, 'Add physical link, details: ' .. link_detail)
redis.call('SADD', KEYS[1], start_port)
redis.call('SADD', KEYS[3], end_port)
redis.call('HSET', KEYS[2], unpack{'BandWidth', bandwidth, 'PhyPeerPort', endport1, 'VlanType', vlan_mode})
redis.call('HSET', KEYS[4], unpack{'BandWidth', bandwidth, 'PhyPeerPort', endport0, 'VlanType', vlan_mode})

return redis.status_reply("Finish adding physical link: " .. link_detail)
