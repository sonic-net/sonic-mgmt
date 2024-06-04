from sonic_py_common.logger import Logger

logger = Logger(log_identifier="memory-test")
logger.set_min_log_priority_info()

begin = 1
end = 10000

while begin <= end:
    logger.log_info('This is a test log: {}'.format(begin))
    begin += 1
