try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from ..common.hv_log import Log
    from ..provisioner.vsp_clpr_provisioner import (
        VSPClprProvisioner,
    )
    from ..model.vsp_clpr_models import (
        ClprInfo,
        ClprInfoList,
        ClprSpec,
    )
    from ..provisioner.vsp_volume_prov import VSPVolumeProvisioner
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
    )
    from common.hv_log import Log
    from ..provisioner.vsp_clpr_provisioner import (
        VSPClprProvisioner,
    )
    from ..model.vsp_clpr_models import ClprInfo, ClprInfoList, ClprSpec
    from provisioner.vsp_volume_prov import VSPVolumeProvisioner
logger = Log()


class VSPClprReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.logger = Log()
        self.connection_info = connection_info
        self.provisioner = VSPClprProvisioner(connection_info, serial)
        self.volume_provisioner = VSPVolumeProvisioner(self.connection_info)
        if state is not None:
            self.state = state
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.provisioner.get_storage_serial()

    def _convert_clpr_capacities(self, clpr_data):
        """Convert CLPR capacities to MB and higher units, convert keys to snake case"""
        if isinstance(clpr_data, dict):
            converted_data = {}
            for key, value in clpr_data.items():
                snake_key = camel_to_snake_case(key)
                if "capacity" in key.lower():
                    # Convert to MB
                    mb_value = value  # * 512 / (1024 * 1024)  # Convert to MB
                    converted_data[f"{snake_key}_in_mb"] = mb_value

                    # Add auto-scaled value (GB or TB)
                    if mb_value >= 1024 * 1024:  # Convert to TB if > 1024 GB
                        converted_data[f"{snake_key}_in_tb"] = mb_value / (1024 * 1024)
                    else:  # Convert to GB
                        converted_data[f"{snake_key}_in_gb"] = mb_value / 1024
                else:
                    converted_data[snake_key] = value
            return converted_data
        return clpr_data

    def get_clpr_facts(self, spec):

        clprs = self.provisioner.get_all_clprs(spec)
        self.logger.writeDebug("RC:get_clpr_facts={}", clprs)

        if clprs is None:
            return "CLPRs not found for {}".format(spec.clpr_id)
        elif isinstance(clprs, ClprInfo):
            clprs = self._convert_clpr_capacities(clprs.to_dict())
            return clprs
        elif isinstance(clprs, ClprInfoList):
            converted_clprs = [
                self._convert_clpr_capacities(c.to_dict()) for c in clprs.data
            ]
            return converted_clprs

        self.logger.writeDebug("RC:get_clpr_facts:clprs={}", clprs)

    @log_entry_exit
    def create_clpr(self, spec):
        """Create a new CLPR"""
        clpr = self.provisioner.create_clpr(spec)
        if clpr:
            return self._convert_clpr_capacities(clpr)
        return None

    @log_entry_exit
    def update_clpr(self, spec):
        """Update CLPR configuration"""
        clpr = self.provisioner.update_clpr(spec)
        if clpr:
            return self._convert_clpr_capacities(clpr)
        return None

    @log_entry_exit
    def delete_clpr(self, spec):
        """Delete a CLPR"""
        return self.provisioner.delete_clpr(spec)

    @log_entry_exit
    def assign_ldev_to_clpr(self, spec):
        """Assign LDEV to CLPR"""
        return self.provisioner.assign_ldev_to_clpr(spec)

    @log_entry_exit
    def assign_parity_group_to_clpr(self, spec):
        """Assign parity group to CLPR"""
        return self.provisioner.assign_parity_group_to_clpr(spec)

    @log_entry_exit
    def clpr_reconcile_direct(self, state: str, spec: ClprSpec):
        """Handle CLPR operations based on state"""
        state = state.lower()
        resp_data = None

        if state == "present":
            resp_data = self.create_clpr(spec)
        elif state == "update":
            resp_data = self.update_clpr(spec)
        elif state == "absent":
            resp_data = self.delete_clpr(spec)
        else:
            return None

        if resp_data:
            logger.writeDebug("RC:resp_data={}  state={}", resp_data, state)
            if isinstance(resp_data, str):
                return resp_data
            elif isinstance(resp_data, (dict, ClprInfo)):
                if isinstance(resp_data, ClprInfo):
                    resp_data = resp_data.to_dict()
                return self._convert_clpr_capacities(resp_data)
        return None
