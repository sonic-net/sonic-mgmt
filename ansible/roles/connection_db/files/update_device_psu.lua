-- KEYS[1] - PSU table key
-- ARGV[1] - PSU
-- ARGV[2] - peer PDU meta
local pdu_table_name = KEYS[1]
local psu = ARGV[1]
local peer_meta = ARGV[2]
local payload = {psu, peer_meta}

redis.log(redis.LOG_NOTICE, 'Add psu ' .. psu .. ' to table ' .. pdu_table_name .. '.')
redis.call('HSET', pdu_table_name, unpack(payload))
return redis.status_reply('Finish adding psu ' .. psu .. ' to table ' .. pdu_table_name .. '.')
