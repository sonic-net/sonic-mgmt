try:
    from ..provisioner.vsp_mp_blade_provisioner import MPBladeProvisioner
except ImportError:
    from provisioner.vsp_mp_blade_provisioner import MPBladeProvisioner


class MpBladeReconciler:
    """
    Reconciler for VSP MP Blade
    """

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = MPBladeProvisioner(self.connection_info)

    def mp_blade_facts(self, spec):
        """
        Get facts about the MP blades.
        """
        return self.provisioner.mp_blade_facts(spec)
