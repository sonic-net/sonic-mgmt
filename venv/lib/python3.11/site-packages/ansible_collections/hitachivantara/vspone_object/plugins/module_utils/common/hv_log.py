# -*- coding: utf-8 -*-

__metaclass__ = type

import logging
import logging.config
import os
import inspect
# import sys
# from time import gmtime, strftime

# try:
#     from enum import Enum
# except ImportError as error:
#     pass

try:
    from .hv_messages import MessageID
    from .hv_constants import TARGET_SUB_DIRECTORY
    from .ansible_common_constants import (
        ANSIBLE_LOG_PATH,
        LOGFILE_NAME,
        LOGGER_LEVEL,
        ROOT_LEVEL,
        LOGFILE_MAX_SIZE,
        LOGFILE_BACKUP_COUNT,
    )

    HAS_MESSAGE_ID = True
except ImportError as error:
    HAS_MESSAGE_ID = False


def setup_logging(logger):
    # Define the log directory and ensure it exists
    # print("ANSIBLE_LOG_PATH={}".format(ANSIBLE_LOG_PATH))
    os.makedirs(ANSIBLE_LOG_PATH, exist_ok=True)

    # Define the log file path
    log_file = os.path.join(ANSIBLE_LOG_PATH, LOGFILE_NAME)

    # Logging configuration dictionary
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "logfileformatter": {"format": "%(asctime)s  pid-%(process)s  %(levelname)s  %(message)s"},
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "logfileformatter",
                "stream": "ext://sys.stderr"
            },
        },
        "loggers": {
            "": {"level": ROOT_LEVEL, "handlers": ["console"]},  # root logger
            "hv_logger": {
                "level": LOGGER_LEVEL,
                "handlers": ["console"],
                "propagate": False,
            },
        },
    }

    # Apply the logging configuration
    logging.config.dictConfig(logging_config)

    # Manually add RotatingFileHandler to the loggers
    log_handler = logging.handlers.RotatingFileHandler(
        log_file, mode="a", maxBytes=LOGFILE_MAX_SIZE, backupCount=LOGFILE_BACKUP_COUNT
    )

    # Use the existing formatter from the configuration
    formatter = logging_config["formatters"]["logfileformatter"]["format"]
    log_handler.setFormatter(logging.Formatter(formatter))

    # Add the handler to the root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    # Add the handler to the hv_logger
    logger.addHandler(log_handler)


def get_ansible_home_dir():
    # Define the base directories to check
    ansible_base_dirs = [
        os.path.expanduser("~/.ansible/collections"),
        "/usr/share/ansible/collections",
    ]

    # Define the target subdirectory to look for

    # Iterate over the base directories to find the target subdirectory
    for base_dir in ansible_base_dirs:
        target_dir = os.path.join(base_dir, TARGET_SUB_DIRECTORY)
        if os.path.exists(target_dir):
            return target_dir

    # Fallback to determining the directory from the current file's location
    abs_path = os.path.dirname(os.path.abspath(__file__))
    split_path = abs_path.split("plugins")[0]

    for base in ansible_base_dirs:
        target_dir = os.path.join(base, split_path)
        if os.path.exists(target_dir):
            return target_dir

    # If none of the directories exist, return the default user-specific directory
    return os.path.join(ansible_base_dirs[0], TARGET_SUB_DIRECTORY)


class Log:

    logger = None

    @staticmethod
    def getHomePath():

        path = os.getenv("HV_STORAGE_MGMT_PATH")
        if path is None:
            path = get_ansible_home_dir()

        return path

    def __init__(self):
        if not Log.logger:
            Log.logger = logging.getLogger("hv_logger")
            setup_logging(Log.logger)

            self.logger = Log.logger
        self.loadMessageIDs()

    def get_previous_frame_info(self):
        frame = inspect.currentframe()
        outer_frames = inspect.getouterframes(frame)
        if len(outer_frames) > 2:
            # Get the previous frame (two levels up)
            previous_frame = outer_frames[2]
            frame_info = {
                "filename": os.path.basename(previous_frame.filename),
                "funcName": previous_frame.function,
                "lineno": previous_frame.lineno,
            }
            return frame_info
        return None

    def loadMessageIDs(self):
        if Log.getHomePath() is not None:
            # $HOME/.ansible/collections/ansible_collections/hitachivantara/vspone_object/messages.properties
            resources = os.path.join(Log.getHomePath(), "messages.properties")
        else:
            resources = "/opt/hitachivantara/ansible/messages.properties"
        self.messageIDs = {}
        if os.path.exists(resources):
            with open(resources) as file:
                for line in file.readlines():
                    (key, value) = line.split("=")
                    self.messageIDs[key.strip()] = value.strip()

    def getMessageIDString(self, messageID, charType, strType):
        if HAS_MESSAGE_ID and isinstance(messageID, MessageID):
            return "[{0}56{1:06X}] {2}".format(
                charType,
                messageID.value,
                self.messageIDs.get(messageID.name, messageID.name),
            )
        else:
            return messageID

    def writeDebug(self, format_string, *args):
        frame_info = self.get_previous_frame_info()
        if args:
            format_string = format_string.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {format_string}"
            if frame_info
            else format_string
        )
        self.logger.debug(msg)

    def writeInfo(self, format_string, *args):
        frame_info = self.get_previous_frame_info()
        if args:
            format_string = format_string.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {format_string}"
            if frame_info
            else format_string
        )
        self.logger.info(msg)

    def writeWarning(self, format_string, *args):
        frame_info = self.get_previous_frame_info()

        if args:
            format_string = format_string.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {format_string}"
            if frame_info
            else format_string
        )
        self.logger.warning(msg)

    def writeError(self, format_string, *args):
        frame_info = self.get_previous_frame_info()

        if args:
            format_string = format_string.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {format_string}"
            if frame_info
            else format_string
        )
        self.logger.error(msg)

    def reportWarningEvent(self, messageID, *args):
        frame_info = self.get_previous_frame_info()
        messageID = self.getMessageIDString(messageID, "W", "WARN")
        if args:
            messageID = messageID.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {messageID}"
            if frame_info
            else messageID
        )
        self.logger.warning(msg)

    def reportErrorEvent(self, messageID, *args):
        frame_info = self.get_previous_frame_info()
        messageID = self.getMessageIDString(messageID, "E", "ERROR")

        if args:
            messageID = messageID.format(*args)
        msg = (
            f"- {frame_info['filename']}  {frame_info['funcName']}:{frame_info['lineno']} - {messageID}"
            if frame_info
            else messageID
        )
        self.logger.error(msg)
