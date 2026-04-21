# Copyright: (c) 2020-2025, Dell Technologies

# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from decimal import Decimal
import re
import traceback
import math
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell.logging_handler \
    import CustomRotatingFileHandler
from ansible.module_utils.basic import missing_required_lib

try:
    import urllib3

    urllib3.disable_warnings()
    HAS_URLLIB3, URLLIB3_IMP_ERR = True, None
except ImportError:
    HAS_URLLIB3, URLLIB3_IMP_ERR = False, traceback.format_exc()

try:
    from storops import UnitySystem
    from storops.unity.client import UnityClient  # noqa   # pylint: disable=unused-import
    from storops.unity.resource import host, cg, snap_schedule, snap, \
        cifs_share, nas_server  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.lun import UnityLun  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.pool import UnityPool, UnityPoolList, RaidGroupParameter  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.filesystem import UnityFileSystem, \
        UnityFileSystemList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.nas_server import UnityNasServer  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.nfs_share import UnityNfsShare, \
        UnityNfsShareList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.snap_schedule import UnitySnapScheduleList, \
        UnitySnapSchedule  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.replication_session import UnityReplicationSession  # noqa   # pylint: disable=unused-import
    from storops.unity.enums import HostInitiatorTypeEnum, \
        TieringPolicyEnum, ScheduleTypeEnum, DayOfWeekEnum, NodeEnum  # noqa   # pylint: disable=unused-import
    from storops.unity.enums import HostLUNAccessEnum, HostTypeEnum, AccessPolicyEnum, \
        FilesystemTypeEnum, FSSupportedProtocolEnum, FSFormatEnum  # noqa   # pylint: disable=unused-import
    from storops.unity.enums import NFSTypeEnum, NFSShareDefaultAccessEnum, NFSShareSecurityEnum, \
        FilesystemSnapAccessTypeEnum, FSLockingPolicyEnum  # noqa   # pylint: disable=unused-import
    from storops.unity.enums import CifsShareOfflineAvailabilityEnum, NasServerUnixDirectoryServiceEnum, \
        KdcTypeEnum, NodeEnum, FileInterfaceRoleEnum, ReplicationOpStatusEnum  # noqa   # pylint: disable=unused-import
    from storops.exception import UnityResourceNotFoundError, \
        StoropsConnectTimeoutError, UnityNfsShareNameExistedError  # noqa   # pylint: disable=unused-import
    from storops.connection.exceptions import HttpError, HTTPClientError  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.user_quota import UnityUserQuota, \
        UnityUserQuotaList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.tree_quota import UnityTreeQuota, \
        UnityTreeQuotaList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.quota_config import UnityQuotaConfig, \
        UnityQuotaConfigList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.storage_resource import UnityStorageResource  # noqa   # pylint: disable=unused-import
    from storops.unity.enums import QuotaPolicyEnum, RaidTypeEnum, \
        RaidStripeWidthEnum, StoragePoolTypeEnum  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.disk import UnityDisk, \
        UnityDiskList, UnityDiskGroup, UnityDiskGroupList  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.cifs_server import UnityCifsServer  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.nfs_server import UnityNfsServer  # noqa   # pylint: disable=unused-import
    from storops.unity.resource.interface import UnityFileInterface  # noqa   # pylint: disable=unused-import

    HAS_UNITY_SDK, STOROPS_IMP_ERR = True, None
except ImportError:
    HAS_UNITY_SDK, STOROPS_IMP_ERR = False, traceback.format_exc()

try:
    from pkg_resources import parse_version
    import pkg_resources

    HAS_PKG_RESOURCE, PKG_RESOURCE_IMP_ERR = True, None
except ImportError:
    HAS_PKG_RESOURCE, PKG_RESOURCE_IMP_ERR = False, traceback.format_exc()


def ensure_required_libs(module):
    """Check required libraries"""

    if not HAS_UNITY_SDK:
        module.fail_json(msg=missing_required_lib("storops"),
                         exception=STOROPS_IMP_ERR)

    if not HAS_PKG_RESOURCE:
        module.fail_json(msg=missing_required_lib("pkg_resources"),
                         exception=PKG_RESOURCE_IMP_ERR)

    if not HAS_URLLIB3:
        module.fail_json(msg=missing_required_lib("urllib3"),
                         exception=URLLIB3_IMP_ERR)

    min_ver = '1.2.12'
    try:
        curr_version = pkg_resources.require("storops")[0].version
    except Exception as err:
        module.fail_json(msg="Failed to get Storops SDK version - "
                             "{0}".format(str(err)))

    if parse_version(curr_version) < parse_version(min_ver):
        module.fail_json(msg="Storops {0} is not supported. "
                             "Required minimum version is "
                             "{1}".format(curr_version, min_ver))


def get_unity_management_host_parameters():
    """Provides common access parameters required for the
    ansible modules on Unity StorageSystem"""

    return dict(
        unispherehost=dict(type='str', required=True, no_log=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', required=False,
                            aliases=['verifycert'], default=True),
        port=dict(type='int', required=False, default=443, no_log=True)
    )


def get_unity_unisphere_connection(module_params, application_type=None):
    """Establishes connection with Unity array using storops SDK"""

    if HAS_UNITY_SDK:
        conn = UnitySystem(host=module_params['unispherehost'],
                           port=module_params['port'],
                           verify=module_params['validate_certs'],
                           username=module_params['username'],
                           password=module_params['password'],
                           application_type=application_type)
        return conn


def get_logger(module_name, log_file_name='ansible_unity.log',
               log_devel=logging.INFO):
    """Intializes and returns the logger object

    :param module_name: Name of module to be part of log message
    :param log_file_name: Name of file in which the log messages get appended
    :param log_devel: Log level
    """

    FORMAT = '%(asctime)-15s %(filename)s %(levelname)s : %(message)s'
    max_bytes = 5 * 1024 * 1024
    logging.basicConfig(filename=log_file_name, format=FORMAT)
    LOG = logging.getLogger(module_name)
    LOG.setLevel(log_devel)
    handler = CustomRotatingFileHandler(log_file_name,
                                        maxBytes=max_bytes,
                                        backupCount=5)
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


def is_input_empty(item):
    """Check whether input string is empty"""

    if item == "" or item.isspace():
        return True
    else:
        return False


def is_size_negative(size):
    """Check whether size is negative"""

    if size and size < 0:
        return True
    else:
        return False


def has_special_char(value):
    """Check whether the string has any special character.
    It allows '_' character"""

    regex = re.compile(r'[@!#$%^&*()<>?/\|}{~:]')
    if regex.search(value) is None:
        return False
    else:
        return True


def is_initiator_valid(value):
    """Validate format of the FC or iSCSI initiator"""

    if value.startswith('iqn') or re.match(r"([A-Fa-f0-9]{2}:){15}[A-Fa-f0-9]{2}", value, re.I) is not None:
        return True
    else:
        return False


def is_valid_netmask(netmask):
    """Validates if ip is valid subnet mask"""

    if netmask:
        regexp = re.compile(r'^((128|192|224|240|248|252|254)\.0\.0\.0)|'
                            r'(255\.(((0|128|192|224|240|248|252|254)\.0\.0)|'
                            r'(255\.(((0|128|192|224|240|248|252|254)\.0)|'
                            r'255\.(0|128|192|224|240|248|252|254)))))$')
        if not regexp.search(netmask):
            return False
        return True
