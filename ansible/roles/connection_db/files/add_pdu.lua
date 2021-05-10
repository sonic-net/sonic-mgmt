-- KEYS[1] - pdu table key
-- KEYS[2] - pdu list key
-- ARGV[1] - JSONified dictinary contains pdu meta

redis.log(redis.LOG_NOTICE, 'Add pdu: ' .. ARGV[1])
local pdu_table_name = KEYS[1]
local pdu_list_name = KEYS[2]
local pdu_meta = cjson.decode(ARGV[1])
local pdu_hostname = pdu_meta['Hostname']
local payload = {}

pdu_meta['Hostname'] = nil

for key, value in pairs(pdu_meta)
do
    table.insert(payload, key)
    table.insert(payload, value)
end

redis.call('SADD', pdu_list_name, pdu_hostname)

redis.call('HSET', pdu_table_name, unpack(payload))
return redis.status_reply('Finish adding pdu: ' .. ARGV[1])
