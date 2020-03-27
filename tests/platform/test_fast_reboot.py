import pytest

@pytest.mark.usefixtures('get_advanced_reboot')
def test_fast_reboot(request, get_advanced_reboot):

    advancedReboot = get_advanced_reboot(rebootType='fast-reboot')
    advancedReboot.runRebootTestcase()
