-- KEYS[1] - test server table key
-- KEYS[2] - test server list key
-- ARGV[1] - JSONified dictinary contains test server meta

redis.log(redis.LOG_NOTICE, 'Add test server: ' .. ARGV[1])
local device_table_name = KEYS[1]
local device_list_name = KEYS[2]
local device_meta = cjson.decode(ARGV[1])
local payload = {'HwSku', device_meta['HwSku'], 'ServerStatus', 'active', 'Type', device_meta['Type']}

if device_meta['ManagementIp'] then
    table.insert(payload, 'ManagementIp')
    table.insert(payload, device_meta['ManagementIp'])
end

redis.call('SADD', device_list_name, device_meta['Hostname'])

redis.call('HSET', device_table_name, unpack(payload))
return redis.status_reply('Finish adding test server: ' .. ARGV[1])
