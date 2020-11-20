import pytest
from spytest import st


@pytest.fixture(scope="module", autouse=True)
def upgrade_module_hooks(request):
    # add things at the start of this module
    yield
    # add things at the end of this module"


@pytest.fixture(scope="function", autouse=True)
def upgrade_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

@pytest.mark.basicsanitytest
@pytest.mark.reload
def test_reboot_dut():
    """
    This test is to reload all the DUTs mentioned as part of TestBed file.
    :return:
    """
    for dut in st.get_dut_names():
        st.reboot(dut)
    st.report_pass("build_reboot_success")

@pytest.mark.basicsanitytest
@pytest.mark.image
def test_upgrade_image():
    """
    This Test is to upgrade all the DUTS mentioned as part of TestBed file.
    user is expected to give the complete http url for "sonicbuilds.yaml--> default--> current"
    :return:
    """
    testurl = st.get_build(st.get_testbed_vars().D1)
    if not testurl:
        st.log("test url is not provided in  sonicbuilds.yaml--> default--> current")
        st.report_fail("build_upgrade_failure")

    for dut in st.get_dut_names():
        st.upgrade_image(dut, testurl)
    st.report_pass("build_upgrade_success")


