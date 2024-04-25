import pytest
from spytest import st
import time


@pytest.fixture(scope="module", autouse=True)
def config_mgmt_vrf():
    """
    Fixture to configure mgmt vrf. Spytest connection ends as there is a prompt reload
    when trying to configure mgmt vrf.
    """
    st.config("SD1", "config vrf add mgmt")
    time.sleep(1)
    st.wait_system_reboot("SD1")
    st.config("SD1", "ip route add default via 10.29.158.1 dev eth0")
    yield
    st.config("SD1", "config vrf del mgmt")
    time.sleep(1)
    st.wait_system_reboot("SD1")
