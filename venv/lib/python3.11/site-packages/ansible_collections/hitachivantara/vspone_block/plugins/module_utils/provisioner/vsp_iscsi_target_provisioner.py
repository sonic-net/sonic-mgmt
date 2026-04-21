try:

    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes, VSPIscsiTargetConstant
    from ..common.hv_log import Log
    from ..model.vsp_host_group_models import GetHostGroupSpec
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes, VSPIscsiTargetConstant
    from common.hv_log import Log
    from model.vsp_host_group_models import GetHostGroupSpec


class VSPIscsiTargetProvisioner:

    def __init__(self, connection_info):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_ISCSI_TARGET
        )

    def get_iscsi_targets(self, spec, serial):
        iscsi_targets = self.gateway.get_iscsi_targets(spec, serial)
        return iscsi_targets

    def get_ports(self, serial):
        return self.gateway.get_ports(serial)

    def get_one_iscsi_target(self, port, name, serial):
        return self.gateway.get_one_iscsi_target(port, name, serial)

    def get_one_iscsi_target_using_id(self, port, id):
        return self.gateway.get_one_iscsi_target(port, None, iscsi_id=id)

    def get_iscsi_targets_by_scan_all_ports(self, name):
        logger = Log()
        lstHg = []
        ports = self.gateway.get_ports()
        for port in ports.data:
            port_id = port.portId
            port_type = port.portType
            logger.writeInfo("port_type = {}", port_type)
            if port_type != VSPIscsiTargetConstant.PORT_TYPE_ISCSI:
                continue

            iscsi_targets = self.gateway.get_iscsi_targets(port_id)
            for iscsi_target in iscsi_targets:
                lstHg.append(iscsi_target)

        return lstHg

    def get_iscsi_target_using_name(self, name, serial):
        iscsi_targets = self.gateway.get_iscsi_targets(None, serial)
        for iscsi_target in iscsi_targets.data:
            if iscsi_target.name == name:
                return iscsi_target
        return None

    # input = (CL4-C, 13)
    def get_iscsi_target_by_id(self, port, id):
        spec = GetHostGroupSpec(ports=[port])
        iscsi_targets = self.get_iscsi_targets(spec, None)
        logger = Log()
        for iscsi_target in iscsi_targets.data:
            if iscsi_target.iscsiId == id:
                return iscsi_target
        return None

    def create_one_iscsi_target(self, iscsi_target_payload, serial):
        self.gateway.create_one_iscsi_target(iscsi_target_payload, serial)

    def set_host_mode(self, iscsi_target, host_mode, host_mode_options, serial):
        self.gateway.set_host_mode(iscsi_target, host_mode, host_mode_options, serial)

    def add_iqn_initiators_to_iscsi_target(self, iscsi_target, iqn_initiators, serial):
        self.gateway.add_iqn_initiators_to_iscsi_target(
            iscsi_target, iqn_initiators, serial
        )

    def delete_iqn_initiators_from_iscsi_target(
        self, iscsi_target, iqn_initiators, serial
    ):
        self.gateway.delete_iqn_initiators_from_iscsi_target(
            iscsi_target, iqn_initiators, serial
        )

    def add_luns_to_iscsi_target(self, iscsi_target, luns, serial):
        self.gateway.add_luns_to_iscsi_target(iscsi_target, luns, serial)

    def delete_luns_from_iscsi_target(self, iscsi_target, luns, serial):
        self.gateway.delete_luns_from_iscsi_target(iscsi_target, luns, serial)

    def add_chap_users_to_iscsi_target(self, iscsi_target, chap_users, serial):
        self.gateway.add_chap_users_to_iscsi_target(iscsi_target, chap_users, serial)

    def delete_chap_users_from_iscsi_target(self, iscsi_target, chap_users, serial):
        self.gateway.delete_chap_users_from_iscsi_target(
            iscsi_target, chap_users, serial
        )

    def delete_iscsi_target(self, iscsi_target, is_delete_all_luns, serial):
        self.gateway.delete_iscsi_target(iscsi_target, is_delete_all_luns, serial)

    def get_all_iscsi_targets(self, serial):
        return self.gateway.get_all_iscsi_target_by_partner_id(serial)

    def update_iqn_nick_name(self, iscsi_target, iqn):
        self.gateway.set_nickname_of_iqn(iscsi_target, iqn)

    def release_host_reservation_status(self, port_id, iscsi_id, lun=None):
        self.gateway.release_host_reservation_status(port_id, iscsi_id, lun)
