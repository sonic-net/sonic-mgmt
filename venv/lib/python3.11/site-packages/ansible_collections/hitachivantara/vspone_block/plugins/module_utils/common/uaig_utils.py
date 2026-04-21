try:
    from ..common.hv_constants import CommonConstants
    from ..common.ansible_common import camel_to_snake_case
    from ..common.hv_log import Log
except ImportError:
    from common.ansible_common import camel_to_snake_case
    from common.hv_log import Log


import hashlib

logger = Log()


def camel_to_snake_case_dict_array(items):
    new_items = []
    if items:
        for item in items:
            new_dict = camel_to_snake_case_dict(item)
            new_items.append(new_dict)
    return new_items


def camel_to_snake_case_dict(response):
    new_dict = {}
    if response is None:
        return
    try:
        for key in response.keys():
            cased_key = camel_to_snake_case(key)
            new_dict[cased_key] = response[key]
    except Exception as ex:
        logger.writeDebug(f"exception in icamel_to_snake_case_dict {ex}")

    return new_dict


class UAIGResourceID:
    """
    This class is used to generate resource id for different resources
    md5 hash is used to generate resource id not to expose the actual value
    This is used to generate resource id for storage, ldev, snapshot, localpair, replpair, journalpool and so on
    nosec: No security issue here as it is does not exploit any security vulnerability
    """

    def get_md5_hash(self, data):
        # hash is used to generate the same resource ID in the UAIG gateway, non-security purposes
        md5_hash = hashlib.md5()
        md5_hash.update(data.encode("utf-8"))
        return md5_hash.hexdigest()

    def storage_resourceId(self, storage_serial_number):
        str_for_hash = f"{storage_serial_number}"
        return f"storage-{self.get_md5_hash(str_for_hash)}"

    def ldev_resourceId(self, storage_serial_number, ldev):
        str_for_hash = f"{storage_serial_number}:{ldev}"
        return f"storagevolume-{self.get_md5_hash(str_for_hash)}"

    def snapshot_resourceId(self, storage_serial_number, pvol, mirror_unit_id):
        storage_resourceId = self.storage_resourceId(storage_serial_number)
        return f"ssp-{storage_resourceId}-{pvol}-{mirror_unit_id}"

    def localpair_resourceId(self, p_vol, s_vol, primary_storage_serial_number):
        str_for_hash = f"{p_vol}:{s_vol}:{primary_storage_serial_number}"
        return f"localpair-{self.get_md5_hash(str_for_hash)}"

    def replpair_resourceId(self, p_vol, s_vol, primary_storage_serial_number):
        str_for_hash = f"{p_vol}:{s_vol}:{primary_storage_serial_number}"
        return f"replpair-{self.get_md5_hash(str_for_hash)}"

    def journal_pool_id(self, storage_serial_number, pool_id):
        str_for_hash = f"{storage_serial_number}:{pool_id}"
        return f"journalpool-{self.get_md5_hash(str_for_hash)}"

    def resource_group_resourceId(self, storage_serial_number, resource_group_name):
        resource_group_name_lower = resource_group_name.lower()
        str_for_hash = f"{storage_serial_number}:{resource_group_name_lower}"
        return f"resourcegroup-{self.get_md5_hash(str_for_hash)}"

    @classmethod
    def getSystemSerial(cls, management_address, remote_gateway_address):
        system_name = CommonConstants.UCP_NAME
        system_serial = CommonConstants.UCP_SERIAL
        system_gateway = management_address
        if remote_gateway_address and remote_gateway_address != "":
            #  expect ip address or fqdn
            hash_obj = hashlib.sha256(remote_gateway_address.encode("utf-8"))
            ss = str(int.from_bytes(hash_obj.digest(), "big"))
            last6 = ss[-6:]
            system_serial = CommonConstants.UCP_SERIAL_PREFIX + last6
            system_name = CommonConstants.UCP_NAME_PREFIX + last6
            system_gateway = remote_gateway_address
        return system_name, system_serial, system_gateway
