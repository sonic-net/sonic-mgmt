import logging
import os.path

try:
    pass
except ImportError:

    # Output expected ImportErrors.

    pass

from logging.config import fileConfig
from logging.handlers import RotatingFileHandler
from time import gmtime, strftime

try:
    from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.hv_messages import (
        MessageID,
    )

    HAS_REQUESTS = True
    HAS_MESSAGE_ID = True
except ImportError:
    HAS_MESSAGE_ID = False


class Logger:

    logger = None

    def __init__(self):
        if not self.logger:

            config = "/opt/hpe/ansible/logger.config"
            if os.path.exists(config):
                with open(config) as file:
                    fileConfig(file)
                self.logger = logging.getLogger("hv_logger")
            else:
                FORMAT = "%(asctime)-15s %(message)s"
                logging.basicConfig(format=FORMAT)
                self.logger = logging.getLogger("hv_logger")
                self.logger.setLevel(logging.INFO)
                handler = RotatingFileHandler(
                    "/var/log/hitachivantara/ansible.log", maxBytes=2048, backupCount=5
                )
                self.logger.addHandler(handler)

            resources = "/opt/hitachivantara/ansible/messages.properties"
            self.messageIDs = {}
            if os.path.exists(resources):
                with open(resources) as file:
                    for line in file.readlines():
                        (key, value) = line.split("=")
                        self.messageIDs[key.strip()] = value.strip()

    def getMessageIDString(self, messageID):
        if HAS_MESSAGE_ID and isinstance(messageID, MessageID):
            return "[{0:06X}] {1}".format(
                messageID.value, self.messageIDs.get(messageID.name, messageID.name)
            )
        else:
            return "[------] {0}".format(messageID)

    def writeInfo(self, messageID, *args):
        messageID = self.getMessageIDString(messageID)

        if args:
            messageID = messageID.format(*args)

        message = strftime("%Y-%m-%d %H:%M:%S ", gmtime()) + messageID
        self.logger.info(message)

    def writeWarning(self, messageID, *args):
        messageID = self.getMessageIDString(messageID)

        if args:
            messageID = messageID.format(*args)

        message = strftime("%Y-%m-%d %H:%M:%S ", gmtime()) + messageID
        self.logger.warning(message)

    def writeError(self, messageID, *args):
        messageID = self.getMessageIDString(messageID)

        if args:
            messageID = messageID.format(*args)

        message = strftime("%Y-%m-%d %H:%M:%S ", gmtime()) + messageID
        self.logger.error(message)

    def writeException(self, exception, messageID, *args):
        messageID = self.getMessageIDString(messageID)

        if args:
            messageID = messageID.format(*args)

        message = strftime("%Y-%m-%d %H:%M:%S {} {}", gmtime()).format(
            messageID, exception
        )
        self.logger.error(message)
