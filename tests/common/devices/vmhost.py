from tests.common.devices.base import AnsibleHostBase


class VMHost(AnsibleHostBase):
    """
    @summary: Class for VM server

    For running ansible module on VM server
    """

    def __init__(self, ansible_adhoc, hostname):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

    @property
    def external_port(self):
        if not hasattr(self, "_external_port"):
            vm = self.host.options["variable_manager"]
            im = self.host.options["inventory_manager"]
            hostvars = vm.get_vars(host=im.get_host(self.hostname), include_delegate_to=False)
            setattr(self, "_external_port", hostvars["external_port"])
        return getattr(self, "_external_port")
