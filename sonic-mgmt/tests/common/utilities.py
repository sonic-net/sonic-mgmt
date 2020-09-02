"""
Utility functions can re-used in testing scripts.
"""
import time
import logging


def wait(seconds, msg=""):
    """
    @summary: Pause specified number of seconds
    @param seconds: Number of seconds to pause
    @param msg: Optional extra message for pause reason
    """
    logging.info("Pause %d seconds, reason: %s" % (seconds, msg))
    time.sleep(seconds)


def wait_until(timeout, interval, condition, *args, **kwargs):
    """
    @summary: Wait until the specified condition is True or timeout.
    @param timeout: Maximum time to wait
    @param interval: Poll interval
    @param condition: A function that returns False or True
    @param *args: Extra args required by the 'condition' function.
    @param **kwargs: Extra args required by the 'condition' function.
    @return: If the condition function returns True before timeout, return True. If the condition function raises an
        exception, log the error and keep waiting and polling.
    """
    logging.debug("Wait until %s is True, timeout is %s seconds, checking interval is %s" % \
        (condition.__name__, timeout, interval))
    start_time = time.time()
    elapsed_time = 0
    while elapsed_time < timeout:
        logging.debug("Time elapsed: %f seconds" % elapsed_time)

        try:
            check_result = condition(*args, **kwargs)
        except Exception as e:
            logging.error("Exception caught while checking %s: %s" % (condition.__name__, repr(e)))
            check_result = False

        if check_result:
            logging.debug("%s is True, exit early with True" % condition.__name__)
            return True
        else:
            logging.debug("%s is False, wait %d seconds and check again" % (condition.__name__, interval))
            time.sleep(interval)
            elapsed_time = time.time() - start_time

    if elapsed_time >= timeout:
        logging.debug("%s is still False after %d seconds, exit with False" % (condition.__name__, timeout))
        return False

def wait_tcp_connection(client, server_hostname, listening_port, timeout_s = 30):
    """
    @summary: Wait until tcp connection is ready or timeout
    @param client: The tcp client host instance
    @param server_hostname: The tcp server hostname
    @param listening_port: Port server is listening on
    @param timeout: Maximum time to wait (30s in default)
    """
    res = client.wait_for(host=server_hostname,
                          port=listening_port,
                          state='started',
                          timeout=timeout_s,
                          module_ignore_errors=True)
    if 'exception' in res:
        logging.warn("Failed to establish TCP connection to %s:%d, timeout=%d" % (str(server_hostname), listening_port, timeout_s))
        return False
    return True
