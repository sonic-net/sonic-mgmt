import pytest

pytestmark = [
    pytest.mark.pretest,
    pytest.mark.topology('util') #special marker
]

def test_announce_routes(fib):
    """Simple test case that utilize fib to announce route in order to a newly setup test bed receive
       BGP routes from remote devices
    """
    assert True
