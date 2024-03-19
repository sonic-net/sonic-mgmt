import pytest

from tests.common.dualtor.data_plane_utils import save_pcap                 # noqa F401


def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_active' ports"
    )

    config.addinivalue_line(
        "markers", "skip_active_standby: mark test to skip running with 'active_standby' ports"
    )

    config.addinivalue_line(
        "markers", "last: mark fixture to run last"
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_generate_tests(metafunc):
    yield
    # HACK: this is to ensure the fixture check_simulator_flap is the
    # one runs last, so the flaps it retrieved reflects the test
    # operations.
    for fixturedef in metafunc._arg2fixturedefs.values():
        fixturedef = fixturedef[0]
        if fixturedef.argname == "check_simulator_flap_counter":
            metafunc.fixturenames.remove(fixturedef.argname)
            metafunc.fixturenames.append(fixturedef.argname)
