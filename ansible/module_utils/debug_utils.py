import os
import re
import logging
from ansible.module_utils.basic import datetime

MAX_LOG_FILES_PER_MODULE = 10


def config_module_logging(module_name, log_path='/tmp', log_level=logging.DEBUG):
    """Tool for configure logging to file for customized ansible modules

    This tool aims to easy the effort for logging in customized ansible modules. To use it in customized ansible
    module, please follow below pattern.
    ```
        from asible.module_utils.debug_utils import config_module_logging

        config_module_logging('your_module_name')

        logging.debug('some message')
        logging.info('some message')
    ```

    After the function is imported and called with ansible module name as argument, then we can simply call
    logging.debug, logging.info, etc., to log a message. The messages are automatically logged to files like:
        /tmp/<ansible_module_name>_<iso_format_timestamp>.log

    The default log path '/tmp' can be changed by passing argument `log_path` when calling this function.

    Another important feature is that this function will also try to remove old log files of this module. The number
    of most recent log files will be kept is specified by the global constant `MAX_LOG_FILES_PER_MODULE`.

    Args:
        module_name (str): Name of the customized ansible module.
        log_path (str, optional): Path of log file. Defaults to '/tmp'.
        log_level (log level, optional): Log level. Defaults to logging.DEBUG.
    """

    # Cleanup old log files to rotate
    pattern = re.compile('{}_[\d\-T:\.]+\.log'.format(module_name))
    existing_log_files = sorted([f for f in os.listdir(log_path) if pattern.match(f)])
    old_log_files = existing_log_files[:-(MAX_LOG_FILES_PER_MODULE-1)]
    try:
        [os.remove(os.path.join(log_path, f)) for f in old_log_files]
    except Exception as e:
        pass

    # Configure logging to file
    curtime = datetime.datetime.now().isoformat()
    log_filename = os.path.join(log_path, '{}_{}.log'.format(module_name, curtime))
    logging.basicConfig(
        filename=log_filename,
        format='%(asctime)s %(levelname)s #%(lineno)d: %(message)s',
        level=log_level)
