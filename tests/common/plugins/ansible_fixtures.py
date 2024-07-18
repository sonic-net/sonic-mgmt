""" This module provides few pytest-ansible fixtures overridden """
import pytest
from pytest_ansible.host_manager import get_host_manager


# Here we override ansible_adhoc fixture from pytest-ansible plugin to overcome
# scope limitation issue; since we want to be able to use ansible_adhoc in module/class scope
# fixtures we have to override the scope here in global conftest.py
# Let's have it with module scope for now, so if something really breaks next test module run will have
# this fixture reevaluated
@pytest.fixture(scope='session')
def ansible_adhoc(request):
    """Return an inventory initialization method."""
    plugin = request.config.pluginmanager.getplugin("ansible")

    # HACK: This is to workaround pytest-ansible plugin issue:
    #     Even no extra-inventory is specified, extra_inventory_manager will still be initialized.
    #     https://github.com/ansible-community/pytest-ansible/issues/135
    # As of today, pytest-ansible supports host manager and module dispatcher v29, v212, v213.
    # While initializing the pytest-ansible plugin, it tries to collect default ansible configurations and
    # command line options. These options are used for creating host manager. When no extra_inventory is specified,
    # the options passed to host manager will include extra_inventory=None. However, the host manager will still
    # try to create extra_inventory_manager with None as the inventory source. This will cause the module dispatcher
    # to run the module on hosts matching host pattern in both inventory and extra inventory. This would cause an
    # ansible module executed twice on the same host. In case we wish to use the shell module to run command like
    # "rm <some_file>" to delete a file. The second run would fail because the file has been deleted in the first run.
    # For more details, please refer to the Github issue mentioned above.
    def _initialize(self, config=None, request=None, **kwargs):
        """Return an initialized Ansible Host Manager instance."""
        ansible_cfg = {}
        # merge command-line configuration options
        if config is not None:
            ansible_cfg.update(self._load_ansible_config(config))
            if "extra_inventory" in ansible_cfg and not ansible_cfg["extra_inventory"]:
                del ansible_cfg["extra_inventory"]
        # merge pytest request configuration options
        if request is not None:
            ansible_cfg.update(self._load_request_config(request))
        # merge in provided kwargs
        ansible_cfg.update(kwargs)

        return get_host_manager(**ansible_cfg)
    plugin.initialize = _initialize.__get__(plugin)

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)
    return init_host_mgr
