import pytest

@pytest.mark.usefixtures('get_advanced_reboot')
def test_fast_reboot(request, get_advanced_reboot):
    '''
    Fast reboot test case is run using advacned reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot')
    advancedReboot.runRebootTestcase()

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot(request, get_advanced_reboot):
    '''
    Warm reboot test case is run using advacned reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    advancedReboot.runRebootTestcase()
