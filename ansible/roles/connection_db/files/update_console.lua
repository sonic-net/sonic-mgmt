-- KEYS[1] - device table key
-- ARGV[1] - console server
-- ARGV[2] - console port

redis.log(redis.LOG_NOTICE, 'Add console info to: ' .. KEYS[1])
local device_table_name = KEYS[1]
local console_server = ARGV[1]
local console_port = ARGV[2]
local payload = {'ConsoleServer', console_server, 'ConsolePort', console_port}

redis.call('HSET', device_table_name, unpack(payload))
return redis.status_reply('Finish adding console info to: ' .. KEYS[1])
