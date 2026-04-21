try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_initial_system_settings_provisioner import (
        InitialSystemSettingsProvisioner,
    )

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from provisioner.vsp_initial_system_settings_provisioner import (
        InitialSystemSettingsProvisioner,
    )
    from common.hv_constants import StateValue


class InitialSystemConfigReconciler:
    """
    Reconciler for SNMP configuration.
    """

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        self.provisioner = InitialSystemSettingsProvisioner(self.connection_info)
        self.serial = serial

    @log_entry_exit
    def snmp_reconcile(self, state: str, spec):
        """
        Reconcile the SNMP configuration based on the desired state in the specification.
        """
        state = state.lower()
        if state == StateValue.PRESENT:
            return self.provisioner.create_update_snmp(spec)
        elif state == StateValue.TEST:
            return self.provisioner.send_test_msg_to_snmp()

    @log_entry_exit
    def snmp_facts(self):
        """
        Get the current SNMP configuration.
        """
        return self.provisioner.get_snmp_facts().camel_to_snake_dict()

    @log_entry_exit
    def audit_log_reconcile(self, state: str, spec):
        """
        Reconcile the audit log configuration based on the desired state in the specification.
        """
        state = state.lower()
        if state == StateValue.PRESENT:
            return self.provisioner.specify_transfer_dest_file_for_audit_log(spec)
        elif state == StateValue.TEST:
            return None, self.provisioner.send_test_msg_to_transfer_destination()

    @log_entry_exit
    def upload_file_reconcile(self, spec):
        """
        Upload the transfer destination file to the VSP system.
        """
        return self.provisioner.specify_transfer_destination_for_audit_log_file(spec)

    @log_entry_exit
    def audit_log_facts(self):
        """
        Get the current audit log configuration.
        """
        return self.provisioner.get_audit_log_file_transfer_destination()
