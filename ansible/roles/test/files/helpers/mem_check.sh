#!/usr/bin/env bash
#
# mem_check.sh
#
#  Check for memory leaks in Redis client output buffers
#  Returns 0 if under threshold, 1 if over threshold
#

REDIS_CLIENT_LIST_OUTPUT_FILE=/tmp/redis_client_list

OMEM_THRESHOLD_BYTES=1048576 # 1MB

TOTAL_OMEM_BYTES=0

# Save 'redis-cli client list' output to temp file
/usr/bin/redis-cli client list > $REDIS_CLIENT_LIST_OUTPUT_FILE

# Extract 'omem' value from each line (client)
while read LINE; do
    OMEM_BYTES=$(echo $LINE | sed 's/.*omem=\([0-9][0-9]*\) .*/\1/')
    TOTAL_OMEM_BYTES=$((TOTAL_OMEM_BYTES += OMEM_BYTES))
done < $REDIS_CLIENT_LIST_OUTPUT_FILE

# Clean up
rm $REDIS_CLIENT_LIST_OUTPUT_FILE

if [ $TOTAL_OMEM_BYTES -gt $OMEM_THRESHOLD_BYTES ]; then
    exit 1
fi

exit 0

