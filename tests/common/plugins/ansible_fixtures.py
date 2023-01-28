""" This module provides few pytest-ansible fixtures overridden """

import pytest

# Here we override ansible_adhoc fixture from pytest-ansible plugin to overcome
# scope limitation issue; since we want to be able to use ansible_adhoc in module/class scope
# fixtures we have to override the scope here in global conftest.py
# Let's have it with module scope for now, so if something really breaks next test module run will have
# this fixture reevaluated
@pytest.fixture(scope='session')
def ansible_adhoc(request):
    """Return an inventory initialization method."""
    plugin = request.config.pluginmanager.getplugin("ansible")

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)
    return init_host_mgr
