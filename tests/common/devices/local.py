from tests.common.devices.base import AnsibleHostBase


class Localhost(AnsibleHostBase):
    """
    @summary: Class for localhost

    For running ansible module on localhost
    """
    def __init__(self, ansible_adhoc):
        AnsibleHostBase.__init__(self, ansible_adhoc, "localhost")
