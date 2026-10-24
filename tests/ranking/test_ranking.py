import pytest


pytestmark = [pytest.mark.topology('ptf')]


def test_ranking_case(ranking_case):
    assert ranking_case['error'] is None, str(ranking_case['error'])
