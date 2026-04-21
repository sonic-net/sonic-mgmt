try:
    from ..provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBVpsHelper:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBVpsProvisioner(self.connection_info)

    @log_entry_exit
    def get_vps_id_by_vps_name(self, vps_name):
        vps_details = SDSBVpsProvisioner(self.connection_info).get_vps_by_name(vps_name)

        if vps_details and "system" not in vps_details.id.lower():
            return vps_details.id
        else:
            return None

    @log_entry_exit
    def is_vps_exist(self, vps_id):
        try:
            vps_details = SDSBVpsProvisioner(self.connection_info).get_vps_by_id(vps_id)
            if vps_details:
                return True
            else:
                return False
        except Exception as e:
            return False
