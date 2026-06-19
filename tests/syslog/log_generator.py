import time
from sonic_py_common.logger import Logger

logger = Logger(log_identifier="rate-limit-test")
logger.set_min_log_priority_info()

begin = 1
end = 101

while begin <= end:
    logger.log_info('This is a test log: {}'.format(begin))
    begin += 1

# Let log flush to file
time.sleep(2)
