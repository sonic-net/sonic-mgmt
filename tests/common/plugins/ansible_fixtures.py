""" This module provides few pytest-ansible fixtures overridden """

import pytest

# Here we override ansible_adhoc fixture from pytest-ansible plugin to overcome
# scope limitation issue; since we want to be able to use ansible_adhoc in module/class scope
# fixtures we have to override the scope here in global conftest.py
# Let's have it with module scope for now, so if something really breaks next test module run will have
# this fixture reevaluated
@pytest.fixture(scope='module')
def ansible_adhoc(request):
    """Return an inventory initialization method."""
    plugin = request.config.pluginmanager.getplugin("ansible")

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)
    return init_host_mgr


# Same as for ansible_adhoc, let's have localhost fixture with session scope
# as it feels that during session run the localhost object should persist unchanged.
# Also, we have autouse=True here to force pytest to evaluate localhost fixture to overcome
# some hidden dependency between localhost and ansible_adhoc (even with default scope) (FIXME)
@pytest.fixture(scope='session', autouse=True)
def localhost(request):
    """Return a host manager representing localhost."""
    # NOTE: Do not use ansible_adhoc as a dependent fixture since that will assert specific command-line parameters have
    # been supplied.  In the case of localhost, the parameters are provided as kwargs below.
    plugin = request.config.pluginmanager.getplugin("ansible")
    return plugin.initialize(request.config, request, inventory='localhost,', connection='local',
                             host_pattern='localhost').localhost
