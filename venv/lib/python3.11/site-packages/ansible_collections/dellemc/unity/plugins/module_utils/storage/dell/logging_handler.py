# Copyright: (c) 2022, Dell Technologies

# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

"""Custom rotating file handler for Unity"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from datetime import datetime
from logging.handlers import RotatingFileHandler


class CustomRotatingFileHandler(RotatingFileHandler):
    def rotation_filename(self, default_name):
        """
        Modify the filename of a log file when rotating.
        :param default_name: The default name of the log file.
        """
        src_file_name = default_name.split('.')
        dest_file_name = "{0}_{1}.{2}.{3}".format(
            src_file_name[0], '{0:%Y%m%d}'.format(datetime.now()),
            src_file_name[1], src_file_name[2]
        )
        return dest_file_name
