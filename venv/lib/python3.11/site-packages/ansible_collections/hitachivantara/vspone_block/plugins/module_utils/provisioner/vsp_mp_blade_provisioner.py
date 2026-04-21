try:
    from ..gateway.vsp_mp_blade_gateway import MPBladeGateway
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from gateway.vsp_mp_blade_gateway import MPBladeGateway
    from common.ansible_common import log_entry_exit


class MPBladeProvisioner:
    """
    Class to provision a blade in a VxRail cluster.
    """

    def __init__(self, connection_info):
        self.gateway = MPBladeGateway(connection_info)

    @log_entry_exit
    def get_all_mp_blades(self):
        """
        Get all MP blades from the VSP API.
        """
        response = self.gateway.get_all_mp_blades()
        return response

    @log_entry_exit
    def get_mp_blade_by_id(self, mp_id):
        single_mp_blade = next(
            (
                mp_blade
                for mp_blade in self.get_all_mp_blades().data
                if mp_blade.mpId == mp_id
            ),
            None,
        )
        return single_mp_blade

    @log_entry_exit
    def mp_blade_facts(self, spec):
        """
        Get facts about the MP blades.
        """
        if spec.mp_id is not None:
            mp_blade = self.get_mp_blade_by_id(spec.mp_id)
            if mp_blade is None:
                raise ValueError(f"MP blade with ID {spec.mp_id} not found.")
            return mp_blade.camel_to_snake_dict()
        else:
            all_mp_blades = self.get_all_mp_blades()
            if all_mp_blades is None:
                raise ValueError("No MP blades found.")
            return all_mp_blades.data_to_snake_case_list()
