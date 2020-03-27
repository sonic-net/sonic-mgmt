import pytest

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad(request, get_advanced_reboot):

    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    advancedReboot.runRebootTestcase()
