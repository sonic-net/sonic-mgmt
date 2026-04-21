# Copyright: (c) 2024-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import math
import re
from datetime import datetime
from decimal import Decimal
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.logging_handler \
    import CustomRotatingFileHandler
import traceback
from ansible.module_utils.basic import missing_required_lib
import random
import string

"""import PyPowerFlex lib"""
try:
    from PyPowerFlex import PowerFlexClient
    from PyPowerFlex.objects.system import SnapshotDef  # pylint: disable=unused-import
    from PyPowerFlex.utils import filter_response  # pylint: disable=unused-import
    HAS_POWERFLEX_SDK, POWERFLEX_SDK_IMP_ERR = True, None
except ImportError:
    HAS_POWERFLEX_SDK, POWERFLEX_SDK_IMP_ERR = False, traceback.format_exc()

"""importing importlib.metadata"""
try:
    from importlib.metadata import version as get_version
    from ansible.module_utils.compat.version import LooseVersion

    PKG_RSRC_IMPORTED, PKG_RSRC_IMP_ERR = True, None
except ImportError:
    PKG_RSRC_IMPORTED, PKG_RSRC_IMP_ERR = False, traceback.format_exc()


def get_powerflex_gateway_host_parameters():
    """Provides common access parameters required for the
    ansible modules on PowerFlex Storage System"""

    return dict(
        hostname=dict(type='str', aliases=['gateway_host'], required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', aliases=['verifycert'], required=False, default=True),
        port=dict(type='int', required=False, default=443),
        timeout=dict(type='int', required=False, default=120)
    )


def get_powerflex_gateway_host_connection(module_params):
    """Establishes connection with PowerFlex storage system"""

    if HAS_POWERFLEX_SDK:
        conn = PowerFlexClient(
            gateway_address=module_params['hostname'],
            gateway_port=module_params['port'],
            verify_certificate=module_params['validate_certs'],
            username=module_params['username'],
            password=module_params['password'],
            timeout=module_params['timeout'])
        conn.initialize()
        return conn


def ensure_required_libs(module):
    """Check required libraries"""

    if not PKG_RSRC_IMPORTED:
        module.fail_json(msg=missing_required_lib("importlib.metadata"),
                         exception=PKG_RSRC_IMP_ERR)

    if not HAS_POWERFLEX_SDK:
        module.fail_json(msg=missing_required_lib("PyPowerFlex V 1.14.1 or above"),
                         exception=POWERFLEX_SDK_IMP_ERR)

    min_ver = '1.14.1'
    try:
        curr_version = get_version("PyPowerFlex")
        supported_version = (LooseVersion(curr_version) >= LooseVersion(min_ver))
        if not supported_version:
            module.fail_json(msg="PyPowerFlex {0} is not supported. "
                             "Required minimum version is "
                             "{1}".format(curr_version, min_ver))
    except Exception as e:
        module.fail_json(msg="Getting PyPowerFlex SDK version, failed with "
                             "Error {0}".format(str(e)))


def get_logger(module_name, log_file_name='ansible_powerflex.log', log_devel=logging.INFO):
    """
    Initialize logger and return the logger object.
    :param module_name: Name of module to be part of log message
    :param log_file_name: Name of file in which the log messages get appended
    :param log_devel: Log level
    :return LOG object
    """
    FORMAT = '%(asctime)-15s %(filename)s %(levelname)s : %(message)s'
    max_bytes = 5 * 1024 * 1024
    logging.basicConfig(filename=log_file_name, format=FORMAT)
    LOG = logging.getLogger(module_name)
    LOG.setLevel(log_devel)
    handler = CustomRotatingFileHandler(log_file_name, maxBytes=max_bytes, backupCount=5)
    formatter = logging.Formatter(FORMAT)
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.propagate = False
    return LOG


KB_IN_BYTES = 1024
MB_IN_BYTES = 1024 * 1024
GB_IN_BYTES = 1024 * 1024 * 1024
TB_IN_BYTES = 1024 * 1024 * 1024 * 1024


def get_size_bytes(size, cap_units):
    """Convert the given size to bytes"""

    if size is not None and size > 0:
        if cap_units in ('kb', 'KB'):
            return size * KB_IN_BYTES
        elif cap_units in ('mb', 'MB'):
            return size * MB_IN_BYTES
        elif cap_units in ('gb', 'GB'):
            return size * GB_IN_BYTES
        elif cap_units in ('tb', 'TB'):
            return size * TB_IN_BYTES
        else:
            return size
    else:
        return 0


def convert_size_with_unit(size_bytes):
    """Convert size in byte with actual unit like KB,MB,GB,TB,PB etc."""

    if not isinstance(size_bytes, int):
        raise ValueError('This method takes Integer type argument only')
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def get_size_in_gb(size, cap_units):
    """Convert the given size to size in GB, size is restricted to 2 decimal places"""

    size_in_bytes = get_size_bytes(size, cap_units)
    size = Decimal(size_in_bytes / GB_IN_BYTES)
    size_in_gb = round(size)
    return size_in_gb


def is_version_less_than_3_6(version):
    """Verifies if powerflex version is less than 3.6"""
    version = re.search(r'R\s*([\d.]+)', version.replace('_', '.')).group(1)
    return \
        LooseVersion(version) < LooseVersion('3.6')


def is_version_less_than_4_6(version):
    """Verifies if powerflex version is less than 3.6"""
    version = re.search(r'R\s*([\d.]+)', version.replace('_', '.')).group(1)
    return \
        LooseVersion(version) < LooseVersion('4.6')


def is_invalid_name(name):
    """Validates string against regex pattern"""
    if name is not None:
        regexp = re.compile(r'^[a-zA-Z0-9!@#$%^~*_-]*$')
        if not regexp.search(name):
            return True


def get_time_minutes(time, time_unit):
    """Convert the given time to minutes"""

    if time is not None and time > 0:
        if time_unit in ('Hour'):
            return time * 60
        elif time_unit in ('Day'):
            return time * 60 * 24
        elif time_unit in ('Week'):
            return time * 60 * 24 * 7
        else:
            return time
    else:
        return 0


def get_display_message(error_text):
    match = re.search(r"displayMessage=([^']+)", error_text)
    error_message = match.group(1) if match else error_text
    return error_message


def validate_date(date):
    try:
        return datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%f')
    except ValueError:
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d')
            return date_obj.replace(hour=0, minute=0, second=0, microsecond=0)
        except ValueError:
            return None


def get_filter(name, id=None):
    filter_type = "id" if id else "name"
    filter_value = id or name
    filter_query = f"eq,{filter_type},{filter_value}"
    return filter_query


def random_uuid_generation():
    """Generate a random UUID using lowercase letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
