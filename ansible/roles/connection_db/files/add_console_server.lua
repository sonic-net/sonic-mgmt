-- KEYS[1] - console server table key
-- KEYS[2] - console server list key
-- ARGV[1] - JSONified dictinary contains console server meta

redis.log(redis.LOG_NOTICE, 'Add console server: ' .. ARGV[1])
local console_table_name = KEYS[1]
local console_list_name = KEYS[2]
local console_server_meta = cjson.decode(ARGV[1])
local console_server_hostname = console_server_meta['Hostname']
local payload = {}

console_server_meta['Hostname'] = nil

for key, value in pairs(console_server_meta)
do
    table.insert(payload, key)
    table.insert(payload, value)
end

redis.call('SADD', console_list_name, console_server_hostname)

redis.call('HSET', console_table_name, unpack(payload))
return redis.status_reply('Finish adding console server: ' .. ARGV[1])
