import time

try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit, dicts_to_dataclass_list
    from ..model.vsp_uvm_models import (
        ExternalIscsiTargets,
        ExternalPortList,
        ExternalPort,
        ExternalLunList,
        ExternalLun,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit, dicts_to_dataclass_list
    from model.vsp_uvm_models import (
        ExternalIscsiTargets,
        ExternalPortList,
        ExternalPort,
        ExternalLunList,
        ExternalLun,
    )


GET_INFO_ISCSI_TAR_PORT_EXT_STORAGE = (
    "v1/objects/iscsi-ports/{}/actions/discover/invoke"
)
REGISTER_ISCSI_NAME_EXT_STORAGE_PORT = (
    "v1/objects/iscsi-ports/{}/actions/register/invoke"
)
GET_ISCSI_NAME_EXT_STORAGE_REGISTER_PORT = "v1/objects/iscsi-ports/{}"
PERFORM_LOGIN_TEST = "v1/objects/iscsi-ports/{}/actions/check/invoke"
GET_EXT_STORAGE_PORTS = "v1/objects/external-storage-ports?portId={}"
GET_EXT_STORAGE_LUNS_FC_PORT = (
    "v1/objects/external-storage-luns?portId={}&externalWwn={}"
)
GET_EXT_STORAGE_LUNS_ISCSI_PORT = (
    "v1/objects/external-storage-luns?portId={}&iscsiIpAddress={}&iscsiName={}"
)
GET_EXT_PATH_GROUPS = "v1/objects/external-path-groups"
GET_ONE_EXT_PATH_GROUP = "v1/objects/external-path-groups/{}"
ADD_EXT_PATH_TO_EXT_PATH_GROUP = (
    "v1/objects/external-path-groups/{}/actions/add-path/invoke"
)
REMOVE_EXT_PATH_FROM_EXT_PATH_GROUP = (
    "v1/objects/external-path-groups/{}/actions/remove-path/invoke"
)
DISCONNECT_FROM_A_VOL_EXT_STORAGE = (
    "v1/objects/external-parity-groups/{}/actions/disconnect/invoke"
)
DELETE_ISCSI_NAME_EXT_STORAGE_PORT = "v1/objects/iscsi-ports/{}/actions/remove/invoke"


logger = Log()


class VSPUvmGateway:
    def __init__(self, connection_info):

        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None
        self.pegasus_model = None

    @log_entry_exit
    def set_storage_serial_number(self, serial=None):
        if serial:
            self.serial = serial
            logger.writeError(f"GW:set_serial={self.serial}")

    @log_entry_exit
    def get_info_iscsi_target_port_ext_storage(self, spec=None):
        if spec is None:
            raise ValueError("spec is None")
        if spec.ports is None or len(spec.ports) == 0:
            raise ValueError("spec.ports is None")
        if spec.external_iscsi_ip_address is None:
            raise ValueError("spec.external_iscsi_ip_address is None")

        parameters = {}
        parameters["iscsiIpAddress"] = spec.external_iscsi_ip_address
        if spec.external_tcp_port:
            parameters["tcpPort"] = spec.external_tcp_port
        payload = {"parameters": parameters}
        end_point = GET_INFO_ISCSI_TAR_PORT_EXT_STORAGE.format(spec.ports[0])
        data = self.connection_manager.post_wo_job(end_point, payload)

        return ExternalIscsiTargets(**data)

    @log_entry_exit
    def register_iscsi_name_ext_storage_port(
        self, port, iscsi_ip_address, iscsi_name, tcp_port=None
    ):

        parameters = {}
        parameters["iscsiIpAddress"] = iscsi_ip_address
        parameters["iscsiName"] = iscsi_name
        if tcp_port:
            parameters["tcpPort"] = tcp_port
        payload = {"parameters": parameters}
        end_point = REGISTER_ISCSI_NAME_EXT_STORAGE_PORT.format(port)
        data = self.connection_manager.post(end_point, payload)
        logger.writeDebug(f"register_iscsi_name_ext_storage_port = {data}")
        return data

    @log_entry_exit
    def get_iscsi_name_ext_storage_register_to_port(self, port):
        logger.writeDebug(f"GW:spec={port}")

        end_point = GET_ISCSI_NAME_EXT_STORAGE_REGISTER_PORT.format(port)
        data = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:data={data}")
        return ExternalIscsiTargets(**data)

    @log_entry_exit
    def perform_login_test(self, port, iscsi_ip_address, iscsi_name):

        parameters = {}
        parameters["iscsiIpAddress"] = iscsi_ip_address
        parameters["iscsiName"] = iscsi_name
        payload = {"parameters": parameters}
        end_point = PERFORM_LOGIN_TEST.format(port)
        data = self.connection_manager.post_wo_job(end_point, payload)

        return data

    @log_entry_exit
    def get_external_storage_ports(self, spec=None):
        if spec is None:
            raise ValueError("spec is None")
        if spec.ports is None or len(spec.ports) == 0:
            raise ValueError("spec.ports is None")

        end_point = GET_EXT_STORAGE_PORTS.format(spec.ports[0])
        data = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:data={data}")
        response = ExternalPortList(dicts_to_dataclass_list(data["data"], ExternalPort))
        return response

    @log_entry_exit
    def get_external_storage_luns_fc_port(self, spec=None):
        if spec is None:
            raise ValueError("spec is None")
        if spec.ports is None or len(spec.ports) == 0:
            raise ValueError("spec.ports is None")
        if spec.external_wwn is None:
            raise ValueError("spec.external_wwn is None")
        end_point = GET_EXT_STORAGE_LUNS_FC_PORT.format(
            spec.ports[0], spec.external_wwn
        )
        luns_data = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:data={luns_data}")
        luns = ExternalLunList(dicts_to_dataclass_list(luns_data["data"], ExternalLun))
        return luns

    @log_entry_exit
    def get_external_storage_luns_iscsi_port(self, spec=None):
        if spec is None:
            raise ValueError("spec is None")
        if spec.ports is None or len(spec.ports) == 0:
            raise ValueError("spec.ports is None")
        if spec.external_iscsi_ip_address is None:
            raise ValueError("spec.iscsi_ip_address is None")
        if spec.external_iscsi_name is None:
            raise ValueError("spec.iscsi_name is None")
        end_point = GET_EXT_STORAGE_LUNS_ISCSI_PORT.format(
            spec.ports[0], spec.external_iscsi_ip_address, spec.external_iscsi_name
        )
        luns_data = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:data={luns_data}")
        luns = ExternalLunList(dicts_to_dataclass_list(luns_data["data"], ExternalLun))
        return luns

    @log_entry_exit
    def get_external_path_groups(self):
        start_time = time.time()
        response = self.connection_manager.get(GET_EXT_PATH_GROUPS)
        logger.writeDebug(f"GW:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_path_groups:time={:.2f} size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        return response

    @log_entry_exit
    def get_one_external_path_group(self, spec=None):
        if spec is None:
            raise ValueError("spec is None")
        if spec.external_path_group_id is None:
            raise ValueError("spec.iscsi_port is None")
        start_time = time.time()
        end_point = GET_ONE_EXT_PATH_GROUP.format(spec.external_path_group_id)
        response = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_path_groups:time={:.2f}",
            end_time - start_time,
        )
        return response

    @log_entry_exit
    def add_external_path_to_path_group_fc(self, external_path_group_id, path):
        parameters = {}
        parameters["portId"] = path.port
        parameters["externalWwn"] = path.external_wwn
        payload = {"parameters": parameters}
        end_point = ADD_EXT_PATH_TO_EXT_PATH_GROUP.format(external_path_group_id)
        try:
            data = self.connection_manager.post(end_point, payload)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    f"GW:add_external_path_to_path_group_fc: "
                    f"Failed to add path: {e}"
                )
                raise e
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def add_external_path_to_path_group_iscsi(self, external_path_group_id, path):
        parameters = {}
        parameters["portId"] = path.port
        parameters["iscsiIpAddress"] = path.external_iscsi_ip_address
        parameters["iscsiName"] = path.external_iscsi_name
        payload = {"parameters": parameters}
        end_point = ADD_EXT_PATH_TO_EXT_PATH_GROUP.format(external_path_group_id)
        try:
            data = self.connection_manager.post(end_point, payload)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    f"GW:add_external_path_to_path_group_iscsi: "
                    f"Failed to add path: {e}"
                )
                raise e
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def remove_external_path_from_path_group_fc(self, external_path_group_id, path):

        parameters = {}
        parameters["portId"] = path.port
        parameters["externalWwn"] = path.external_wwn
        payload = {"parameters": parameters}
        end_point = REMOVE_EXT_PATH_FROM_EXT_PATH_GROUP.format(external_path_group_id)
        try:
            data = self.connection_manager.post(end_point, payload)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    f"GW:remove_external_path_from_path_group_fc: "
                    f"Failed to remove path: {e}"
                )
                raise e
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def remove_external_path_from_path_group_iscsi(self, external_path_group_id, path):

        parameters = {}
        parameters["portId"] = path.port
        parameters["iscsiIpAddress"] = path.external_iscsi_ip_address
        parameters["iscsiName"] = path.external_iscsi_name
        payload = {"parameters": parameters}
        end_point = REMOVE_EXT_PATH_FROM_EXT_PATH_GROUP.format(external_path_group_id)
        try:
            data = self.connection_manager.post(end_point, payload)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    f"GW:remove_external_path_from_path_group_iscsi: "
                    f"Failed to remove path: {e}"
                )
                raise e
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, external_parity_group):
        end_point = DISCONNECT_FROM_A_VOL_EXT_STORAGE.format(external_parity_group)
        data = self.connection_manager.post(end_point, data=None)
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def delete_iscsi_name_of_external_storage_from_port(
        self, port, iscsi_ip_address, iscsi_name
    ):

        logger.writeDebug(f"GW:delete_iscsi_name_of_external_storage_from_port={port}")
        parameters = {}
        parameters["iscsiIpAddress"] = iscsi_ip_address
        parameters["iscsiName"] = iscsi_name

        payload = {"parameters": parameters}
        end_point = DELETE_ISCSI_NAME_EXT_STORAGE_PORT.format(port)
        data = self.connection_manager.post(end_point, payload)
        logger.writeDebug(
            f"GW:delete_iscsi_name_of_external_storage_from_port:data={data}"
        )
        self.connection_info.changed = True
        return data
