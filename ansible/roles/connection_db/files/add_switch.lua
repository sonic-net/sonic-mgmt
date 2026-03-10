-- KEYS[1] - switch table key
-- KEYS[2] - DUT list key
-- ARGV[1] - JSONified dictinary contains switch meta

redis.log(redis.LOG_NOTICE, 'Add switch: ' .. ARGV[1])
local switch_table_name = KEYS[1]
local dut_list_name = KEYS[2]
local switch_meta = cjson.decode(ARGV[1])
local switch_type = switch_meta['Type']
local payload = {'HwSku', switch_meta['HwSku']}

if switch_meta['ManagementIp'] then
  table.insert(payload, 'ManagementIp')
  table.insert(payload, switch_meta['ManagementIp'])
end

if string.find(switch_type, 'FanoutLeaf') then
  table.insert(payload, 'Type')
  table.insert(payload, 'leaf_fanout')
elseif string.find(switch_type, 'FanoutRoot') then
  table.insert(payload, 'Type')
  table.insert(payload, 'root_fanout')
elseif switch_type == 'DevSonic' then
  table.insert(payload, 'Type')
  table.insert(payload, 'dev_sonic')
  table.insert(payload, 'ProvisionStatus')
  table.insert(payload, 'not_provisioned')
  redis.call('SADD', dut_list_name, switch_meta['Hostname'])
else
  return redis.error_reply('Unsupported device: ' .. ARGV[1])
end

redis.call('HSET', switch_table_name, unpack(payload))
return redis.status_reply('Finish adding switch: ' .. ARGV[1])
