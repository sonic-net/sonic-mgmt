import http.client
import ssl

try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.sdsb_storage_node_models import (
        SDSBStorageNodeInfo,
        SDSBStorageNodeInfoList,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.sdsb_storage_node_models import (
        SDSBStorageNodeInfo,
        SDSBStorageNodeInfoList,
    )

GET_STORAGE_NODES = "v1/objects/storage-nodes"
GET_STORAGE_NODES_WITH_QUERY = "v1/objects/storage-nodes{}"
GET_STORAGE_NODE_BY_ID = "v1/objects/storage-nodes/{}"
BLOCK_FOR_MAINTENANCE = (
    "v1/objects/storage-nodes/{}/actions/block-for-maintenance/invoke"
)
RESTORE_FROM_MAINTENANCE = "v1/objects/storage-nodes/{}/actions/recover/invoke"
GET_CAPACITY_SETTINGS = "v1/objects/storage-node-capacity-settings"
GET_CAPACITY_SETTING_OF_A_STORAGE_NODE = "v1/objects/storage-node-capacity-settings/{}"
EDIT_CAPACITY_SETTING_OF_A_STORAGE_NODE = "v1/objects/storage-node-capacity-settings/{}"


logger = Log()


class SDSBStorageNodeDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(
        self,
        fault_domain_id=None,
        name=None,
        cluster_role=None,
        protection_domain_id=None,
    ):
        params = {}
        if fault_domain_id:
            params["faultDomainId"] = fault_domain_id
        if name:
            params["name"] = name
        if cluster_role:
            params["clusterRole"] = cluster_role
        if protection_domain_id:
            params["protectionDomainId"] = protection_domain_id

        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_storage_nodes(
        self,
        fault_domain_id=None,
        name=None,
        cluster_role=None,
        protection_domain_id=None,
    ):
        if (
            fault_domain_id is None
            and name is None
            and cluster_role is None
            and protection_domain_id is None
        ):
            end_point = GET_STORAGE_NODES
        else:
            query = self.get_query_parameters(
                fault_domain_id, name, cluster_role, protection_domain_id
            )
            end_point = GET_STORAGE_NODES_WITH_QUERY.format(query)

        storage_node_data = self.connection_manager.get(end_point)
        storage_node_data = self.fill_capacity_settings(storage_node_data)
        storage_node_data = self.inject_cluster_master_primary(storage_node_data)

        return SDSBStorageNodeInfoList(
            dicts_to_dataclass_list(storage_node_data["data"], SDSBStorageNodeInfo)
        )

    @log_entry_exit
    def fill_capacity_settings(self, storage_node_data):
        capacity_settings = self.get_capacity_settings()
        logger.writeDebug(
            f"GW:fill_capacity_settings:capacity_settings={capacity_settings}"
        )
        id_to_capacity_map = {}
        for x in capacity_settings["data"]:
            id_to_capacity_map[x["id"]] = x["capacityBalancingSetting"]["isEnabled"]

        for sn in storage_node_data["data"]:
            value = id_to_capacity_map.get(sn["id"], None)
            if value:
                sn["is_capacity_balancing_enabled"] = value

        logger.writeDebug(f"GW:fill_capacity_settings:resp={storage_node_data}")
        return storage_node_data

    @log_entry_exit
    def inject_cluster_master_primary(self, storage_node_data):
        for sn in storage_node_data["data"]:
            value = sn["controlPortIpv4Address"]
            logger.writeDebug(f"GW:inject_cluster_master_primary:resp={value}")
            master_flag = self.get_storage_master_flag(value)
            sn["isStorageMasterNodePrimary"] = master_flag
        return storage_node_data

    @log_entry_exit
    def block_node_for_maintenance(self, id):
        end_point = BLOCK_FOR_MAINTENANCE.format(id)
        resp = self.connection_manager.post(end_point, data=None)
        logger.writeDebug(f"GW:block_node_for_maintenance:resp={resp}")
        return resp

    @log_entry_exit
    def restore_from_maintenance(self, id):
        end_point = RESTORE_FROM_MAINTENANCE.format(id)
        resp = self.connection_manager.post(end_point, data=None)
        logger.writeDebug(f"GW:restore_from_maintenance:resp={resp}")
        return resp

    @log_entry_exit
    def get_storage_node_by_id(self, id):
        end_point = GET_STORAGE_NODE_BY_ID.format(id)
        storage_node_data = self.connection_manager.get(end_point)
        capacity_saving = self.get_capacity_settings_of_a_storage_node(id)
        logger.writeDebug(
            f"GW:get_storage_node_by_id:capacity_saving={capacity_saving}"
        )
        storage_node = SDSBStorageNodeInfo(**storage_node_data)
        storage_node.is_capacity_balancing_enabled = capacity_saving[
            "capacityBalancingSetting"
        ]["isEnabled"]
        storage_node.isStorageMasterNodePrimary = self.get_storage_master_flag(
            storage_node.controlPortIpv4Address
        )
        return storage_node

    @log_entry_exit
    def get_capacity_settings_of_a_storage_node(self, id):
        end_point = GET_CAPACITY_SETTING_OF_A_STORAGE_NODE.format(id)
        capacity_settings = self.connection_manager.get(end_point)
        logger.writeDebug(
            f"GW:get_capacity_settings_storage_node:capacity_saving={capacity_settings}"
        )
        return capacity_settings

    @log_entry_exit
    def get_capacity_settings(self):
        end_point = GET_CAPACITY_SETTINGS
        capacity_settings = self.connection_manager.get(end_point)
        logger.writeDebug(
            f"GW:get_capacity_settings:capacity_saving={capacity_settings}"
        )
        return capacity_settings

    @log_entry_exit
    def edit_capacity_settings_of_a_storage_node(
        self, id, is_capacity_balancing_enabled
    ):
        end_point = EDIT_CAPACITY_SETTING_OF_A_STORAGE_NODE.format(id)
        payload = {
            "capacityBalancingSetting": {"isEnabled": is_capacity_balancing_enabled}
        }
        resp = self.connection_manager.patch(end_point, data=payload)
        logger.writeDebug(
            f"GW:edit_capacity_settings_of_a_storage_node:capacity_saving={resp}"
        )
        return resp

    def get_storage_master_flag(self, host):
        # Create SSL context that ignores certificate verification (-k option in curl)
        context = ssl._create_unverified_context()  # nosec

        # Define host and endpoint
        # host = "10.76.47.53"
        end_point = "/ConfigurationManager/simple/configuration/storage-master-node-primary-flag"

        try:
            # Open HTTPS connection
            conn = http.client.HTTPSConnection(host, context=context)

            # Send GET request
            conn.request("GET", end_point)

            # Get response
            response = conn.getresponse()

            # # Print response status, headers, and body
            # print("Status:", response.status, response.reason)
            # print("Headers:")
            # for header, value in response.getheaders():
            #     print(f"{header}: {value}")

            # body = response.read().decode("utf-8", errors="ignore")
            # print("\nBody:")
            # print(body)
            if response.status == 200:
                ret_value = True
            else:
                ret_value = False

            conn.close()
            return ret_value
        except Exception as e:
            logger.writeDebug(f"GW:get_storage_master_flag:Error={e}")
