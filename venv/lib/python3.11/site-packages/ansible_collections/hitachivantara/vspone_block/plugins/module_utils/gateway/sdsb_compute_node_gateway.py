try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.sdsb_compute_node_models import (
        SDSBComputeNodesInfo,
        SDSBComputeNodeInfo,
        NameIdPair,
        HbaPathInfo,
    )
    from ..model.sdsb_port_models import SDSBComputePortInfo, SDSBComputePortsInfo
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from model.sdsb_compute_node_models import (
        SDSBComputeNodesInfo,
        SDSBComputeNodeInfo,
        NameIdPair,
        HbaPathInfo,
    )
    from model.sdsb_port_models import SDSBComputePortInfo, SDSBComputePortsInfo
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBComputeNodeDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(self, spec):
        params = {}
        if spec.names is not None:
            if len(spec.names) == 1:
                params["nickname"] = spec.names[0]
            else:
                params["nicknames"] = ",".join(spec.names)
        if spec.hba_name is not None:
            params["hbaName"] = ",".join(spec.hba_name)
        if spec.vps_id is not None:
            params["vpsId"] = spec.vps_id

        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_compute_nodes(self, spec=None):

        end_point = SDSBlockEndpoints.GET_SERVERS
        if spec is not None:
            end_point = end_point + self.get_query_parameters(spec)
        compute_node_data = self.connection_manager.get(end_point)

        return SDSBComputeNodesInfo(
            dicts_to_dataclass_list(compute_node_data["data"], SDSBComputeNodeInfo)
        )

    @log_entry_exit
    def get_compute_port_ids(self):
        end_point = SDSBlockEndpoints.GET_PORTS
        compute_ports_data = self.connection_manager.get(end_point)
        data = compute_ports_data["data"]

        port_id_list = []
        for x in data:
            port_id_list.append(x.get("id"))

        return port_id_list

    @log_entry_exit
    def get_compute_ports(self, spec):
        end_point = SDSBlockEndpoints.GET_PORTS
        if spec.names is not None:
            if spec.names and len(spec.names) > 0:
                if len(spec.names) == 1:
                    key = "name"
                    val = spec.names[0]
                else:
                    key = "names"
                    val = ",".join(spec.names)
                end_point = SDSBlockEndpoints.GET_PORTS_AND_QUERY.format(key, val)

        compute_ports_data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_compute_ports:compute_ports_data={}", compute_ports_data
        )
        return SDSBComputePortsInfo(
            dicts_to_dataclass_list(compute_ports_data["data"], SDSBComputePortInfo)
        )

    @log_entry_exit
    def get_compute_node_hba_ids(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]
        logger.writeDebug("GW:get_compute_node_hba_ids:data={}", data)

        hba_id_list = []
        for x in data:
            if x.get("protocol") == "iSCSI":
                hba_id_list.append(x.get("id"))

        return hba_id_list

    @log_entry_exit
    def get_compute_node_iscsi_pairs(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]
        logger.writeDebug("GW:get_compute_node_nqn_ids:data={}", data)

        iscsi_name_id_map = {}
        for x in data:
            if x.get("protocol") == "iSCSI":
                iscsi_name_id_map[x.get("name")] = x.get("id")

        return iscsi_name_id_map

    @log_entry_exit
    def get_compute_node_nqn_ids(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]
        logger.writeDebug("GW:get_compute_node_nqn_ids:data={}", data)

        hba_id_list = []
        for x in data:
            if x.get("protocol") == "NVMe_TCP":
                hba_id_list.append(x.get("id"))

        return hba_id_list

    @log_entry_exit
    def get_compute_node_nqn_pairs(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]
        logger.writeDebug("GW:get_compute_node_nqn_ids:data={}", data)

        nqn_name_id_map = {}
        for x in data:
            if x.get("protocol") == "NVMe_TCP":
                nqn_name_id_map[x.get("name")] = x.get("id")

        return nqn_name_id_map

    @log_entry_exit
    def get_compute_node_hba_name_id_pairs(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]

        logger.writeDebug("GW:get_compute_node_hba_name_id_pairs:data={}", data)
        hba_list = []
        for x in data:
            if x.get("protocol") == "iSCSI":
                pair = NameIdPair(x.get("name"), x.get("id"))
                hba_list.append(pair)

        return hba_list

    @log_entry_exit
    def get_compute_node_nqn_name_id_pairs(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]

        logger.writeDebug("GW:get_compute_node_nqn_name_id_pairs:data={}", data)
        hba_list = []
        for x in data:
            if x.get("protocol") == "NVMe_TCP":
                pair = NameIdPair(x.get("name"), x.get("id"))
                hba_list.append(pair)

        return hba_list

    @log_entry_exit
    def get_compute_node_hba_names(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]

        logger.writeDebug("GW:get_compute_node_hba_names:data={}", data)
        hba_name_list = []
        for x in data:
            if x.get("protocol") == "iSCSI":
                hba_name_list.append(x.get("name"))

        return hba_name_list

    @log_entry_exit
    def get_compute_node_nqn_names(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_HBAS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        hba_data = self.connection_manager.get(end_point)
        data = hba_data["data"]

        logger.writeDebug("GW:get_compute_node_nqn_names:data={}", data)
        hba_name_list = []
        for x in data:
            if x.get("protocol") == "NVMe_TCP":
                hba_name_list.append(x.get("name"))

        return hba_name_list

    @log_entry_exit
    def get_volume_compute_node_ids(self, vol_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_VOLUME_SERVER_CONNECTIONS_FOR_VOLUMEID.format(
            vol_id
        )
        if vps_id:
            end_point += f"&vpsId={vps_id}"
        volume_data = self.connection_manager.get(end_point)
        data = volume_data["data"]

        logger.writeDebug("GW:get_volume_compute_node_ids:data={}", data)
        server_id_list = []
        for x in data:
            server_id_list.append(x.get("serverId"))

        return server_id_list

    @log_entry_exit
    def get_compute_node_volume_ids(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_VOLUME_SERVER_CONNECTIONS_FOR_SERVERID.format(
            compute_node_id
        )
        if vps_id:
            end_point += f"&vpsId={vps_id}"
        volume_data = self.connection_manager.get(end_point)
        data = volume_data["data"]

        logger.writeDebug("GW:get_compute_node_volume_ids:data={}", data)
        vol_id_list = []
        for x in data:
            vol_id_list.append(x.get("volumeId"))

        return vol_id_list

    @log_entry_exit
    def get_hba_paths(self, compute_node_id, vps_id=None):
        end_point = SDSBlockEndpoints.GET_PATHS.format(compute_node_id)
        if vps_id:
            end_point += f"?vpsId={vps_id}"
        data = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_hba_paths:data={}", data)
        return dicts_to_dataclass_list(data["data"], HbaPathInfo)

    @log_entry_exit
    def get_compute_node_by_id(self, id):
        end_point = SDSBlockEndpoints.GET_SERVER_BY_ID.format(id)
        data = self.connection_manager.get(end_point)
        return SDSBComputeNodeInfo(**data)
        # return dicts_to_dataclass_list(compute_node_data, SDSBComputeNodeInfo)

    @log_entry_exit
    def get_compute_node_by_name(self, name, vps_id=None):
        end_point = SDSBlockEndpoints.GET_SERVERS_AND_QUERY_NICKNAME.format(name)
        if vps_id:
            end_point += f"&vpsId={vps_id}"
        data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_compute_node_by_name:data={} len={}", data, len(data.get("data"))
        )
        if data is not None and len(data.get("data")) > 0:
            return SDSBComputeNodeInfo(**data.get("data")[0])
        else:
            return None

    @log_entry_exit
    def delete_compute_node_by_id(self, id, vps_id=None):
        end_point = SDSBlockEndpoints.DELETE_SERVERS.format(id)
        body = None
        if vps_id:
            body = {"vpsId": vps_id}
        data = self.connection_manager.delete(end_point, data=body)
        return data
        # return SDSBComputeNodesInfo(**data)

    @log_entry_exit
    def create_compute_node(self, name, os_type, vps_id=None):
        body = {
            "serverNickname": str(name),
            "osType": str(os_type),
        }
        if vps_id:
            body["vpsId"] = vps_id
        end_point = SDSBlockEndpoints.POST_SERVERS
        data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:create_compute_node:data={}", data)
        return data
        # return SDSBComputeNodesInfo(**data)

    @log_entry_exit
    def add_iqn_to_compute_node(self, compute_node_id, iqn, vps_id=None):
        body = {
            "protocol": "iSCSI",
            "iscsiName": str(iqn),
        }
        if vps_id:
            body["vpsId"] = vps_id
        logger.writeDebug("GW:add_iqn_to_compute_node:body={}", body)
        end_point = SDSBlockEndpoints.POST_HBAS.format(compute_node_id)
        data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:add_iqn_to_compute_node:data={}", data)
        return data

    @log_entry_exit
    def add_nqn_to_compute_node(self, compute_node_id, nqn, vps_id=None):
        body = {
            "protocol": "NVMe_TCP",
            "hostNqn": str(nqn),
        }
        if vps_id:
            body["vpsId"] = vps_id
        logger.writeDebug("GW:add_nqn_to_compute_node:body={}", body)
        end_point = SDSBlockEndpoints.POST_HBAS.format(compute_node_id)
        data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:add_nqn_to_compute_node:data={}", data)
        return data

    @log_entry_exit
    def add_compute_node_path(self, compute_node_id, hba_id, port_id, vps_id=None):
        body = {
            "hbaId": str(hba_id),
            "portId": str(port_id),
        }
        if vps_id:
            body["vpsId"] = vps_id
        logger.writeDebug("GW:add_compute_node_path:body={}", body)
        end_point = SDSBlockEndpoints.POST_PATHS.format(compute_node_id)
        data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:add_compute_node_path:data={}", data)
        return data

    @log_entry_exit
    def attach_volume_to_compute_node(self, compute_node_id, volume_id, vps_id=None):
        body = {
            "volumeId": str(volume_id),
            "serverId": str(compute_node_id),
        }
        if vps_id:
            body["vpsId"] = vps_id
        logger.writeDebug("GW:attach_volume_to_compute_node:body={}", body)
        end_point = SDSBlockEndpoints.POST_VOLUME_SERVER_CONNECTIONS
        data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:attach_volume_to_compute_node:data={}", data)
        return data

    @log_entry_exit
    def update_compute_node(self, compute_node_id, spec):
        body = {
            "nickname": str(spec.name),
            "osType": str(spec.os_type),
        }
        if spec.vps_id:
            body["vpsId"] = spec.vps_id
        logger.writeDebug("GW:update_compute_node:body={}", body)
        end_point = SDSBlockEndpoints.PATCH_SERVERS.format(compute_node_id)
        data = self.connection_manager.patch(end_point, body)
        logger.writeDebug("GW:update_compute_node:data={}", data)
        return data

    @log_entry_exit
    def delete_hba_path(self, compute_node_id, hba_port_id_pair, vps_id=None):
        end_point = SDSBlockEndpoints.DELETE_PATHS.format(
            compute_node_id, hba_port_id_pair.hba_id, hba_port_id_pair.port_id
        )
        body = None
        if vps_id:
            body = {"vpsId": vps_id}
        data = self.connection_manager.delete(end_point, body)
        return data

    @log_entry_exit
    def delete_hba(self, compute_node_id, hba_id, vps_id=None):
        end_point = SDSBlockEndpoints.DELETE_HBAS.format(compute_node_id, hba_id)
        body = None
        if vps_id:
            body = {"vpsId": vps_id}
        data = self.connection_manager.delete(end_point, body)
        return data

    @log_entry_exit
    def detach_volume_from_compute_node(
        self, compute_node_id, vol_id_to_detach, vps_id=None
    ):
        end_point = SDSBlockEndpoints.DELETE_VOLUME_SERVER_CONNECTIONS.format(
            vol_id_to_detach, compute_node_id
        )
        body = None
        if vps_id:
            body = {"vpsId": vps_id}
        data = self.connection_manager.delete(end_point, body)
        return data
