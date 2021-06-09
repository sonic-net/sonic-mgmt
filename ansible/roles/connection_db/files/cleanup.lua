-- ARGV[1:] glob-style key pattern to remove

local result = 0
for i = 1, #ARGV, 1 do
    local matches = redis.call('KEYS', ARGV[i])
    if next(matches) ~= nil then
        for _, key in ipairs(matches) do
            result = result + redis.call('DEL', key)
        end
    end
end

return result
