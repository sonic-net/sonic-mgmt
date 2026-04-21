try:
    from ..provisioner.sdsb_port_provisioner import SDSBPortProvisioner
    from ..provisioner.sdsb_port_auth_provisioner import SDSBPortAuthProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case, replace_nulls
    from ..model.sdsb_port_models import SDSBPortDetailInfoList, SDSBPortDetailInfo
    from ..message.sdsb_port_msgs import SDSBPortValidationMsg
except ImportError:
    from provisioner.sdsb_port_provisioner import SDSBPortProvisioner
    from provisioner.sdsb_port_auth_provisioner import SDSBPortAuthProvisioner
    from common.hv_log import Log
    from common.sdsb_utils import convert_keys_to_snake_case, replace_nulls
    from common.ansible_common import log_entry_exit
    from model.sdsb_port_models import SDSBPortDetailInfoList, SDSBPortDetailInfo
    from message.sdsb_port_msgs import SDSBPortValidationMsg

logger = Log()


class SDSBPortReconciler:
    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBPortProvisioner(self.connection_info)
        self.port_auth_prov = SDSBPortAuthProvisioner(self.connection_info)

    @log_entry_exit
    def get_compute_ports(self, spec=None):
        ports = self.provisioner.get_compute_ports(spec)
        logger.writeDebug("RC:get_compute_ports:ports={}", ports)
        detail_ports = self.get_detail_ports(ports.data)

        logger.writeDebug("RC:get_compute_ports:detail_ports={}", detail_ports)
        return SDSBPortDetailInfoList(data=detail_ports)

    @log_entry_exit
    def get_detail_ports(self, ports):
        port_detail_list = []

        for port in ports:
            port_id = port.id
            pd = self.get_detail_port(port_id)
            port_detail_list.append(pd)
        logger.writeDebug("RC:get_compute_ports:port_detail_list={}", port_detail_list)
        return port_detail_list

    @log_entry_exit
    def get_detail_port(self, port_id):
        port = self.provisioner.get_port_by_id(port_id)
        port_auth_info = self.port_auth_prov.get_port_auth_settings(port_id)
        chap_user_info = self.port_auth_prov.get_port_chap_users(port_id)
        pd = SDSBPortDetailInfo(
            portInfo=port,
            portAuthInfo=port_auth_info,
            chapUsersInfo=chap_user_info.data,
        )
        return pd

    @log_entry_exit
    def reconcile_compute_port(self, spec):
        if spec.protocol is None and spec.id is None:
            raise ValueError(SDSBPortValidationMsg.INVALID_INPUT.value)
        if spec.protocol:
            resp = self.change_compute_port_protocol(spec)
            return resp
        if spec.id:
            resp = self.edit_compute_port_settings(spec)
            return resp

    @log_entry_exit
    def change_compute_port_protocol(self, spec):
        protocol_map = {"iscsi": "iSCSI", "nvme_tcp": "NVMe_TCP"}
        all_ports = self.provisioner.get_compute_ports()
        logger.writeDebug(
            "RC:reconcile_compute_port:change_compute_port_protocol:all_ports={}",
            all_ports,
        )
        port_protocol = all_ports.data[0].protocol
        if port_protocol != protocol_map.get(spec.protocol):
            port = self.provisioner.change_compute_port_protocol(spec.protocol)
            logger.writeDebug(
                "RC:reconcile_compute_port:change_compute_port_protocol:port={}", port
            )
            self.connection_info.changed = True
        # all_ports = self.provisioner.get_compute_ports()
        converted = convert_keys_to_snake_case(all_ports.data_to_list())
        return replace_nulls(converted)

    @log_entry_exit
    def edit_compute_port_settings(self, spec):
        port = self.provisioner.get_port_by_id(spec.id)
        logger.writeDebug(
            "RC:reconcile_compute_port:edit_compute_port_settings={}", port
        )
        changed = False
        name = None
        nick_name = None
        if spec.nick_name and port.nickname != spec.nick_name:
            changed = True
            nick_name = spec.nick_name
        if spec.name and port.protocol == "iSCSI" and port.name != spec.name:
            changed = True
            name = spec.name
        if changed:
            self.connection_info.changed = True
            unused = self.provisioner.edit_compute_port_settings(
                spec.id, nick_name, name
            )
        port = self.provisioner.get_port_by_id(spec.id)
        converted = convert_keys_to_snake_case(port.to_dict())
        return replace_nulls(converted)
