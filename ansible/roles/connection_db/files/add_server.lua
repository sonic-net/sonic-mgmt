-- KEYS[1] - server table key
-- ARGV[1] - JSONified dictinary contains server meta

redis.log(redis.LOG_NOTICE, 'Add server: ' .. ARGV[1])
local device_table_name = KEYS[1]
local device_meta = cjson.decode(ARGV[1])
local payload = {'HwSku', device_meta['HwSku'], 'ServerStatus', 'active'}

if device_meta['ManagementIp'] then
    table.insert(payload, 'ManagementIp')
    table.insert(payload, device_meta['ManagementIp'])
end

redis.call('HSET', device_table_name, unpack(payload))
return redis.status_reply('Finish adding server: ' .. ARGV[1])
