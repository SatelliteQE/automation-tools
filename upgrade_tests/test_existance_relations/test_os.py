"""Upgrade TestSuite for validating OS in Satellite existence post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('os', 'title'))
def test_positive_os_by_title(pre, post):
    """Test all OS are existing post upgrade by their title

    :id: faf14fe0-cd2d-4c27-ad3a-eb631820eaa1

    :assert: All OS should be retained post upgrade by their title
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('os', 'family'))
def test_positive_os_by_family(pre, post):
    """Test all OS are existing post upgrade by their families

    :id: de83ceca-1dd5-4e20-a815-91d348b79e29

    :assert: All OS should be retained post upgrade by their families
    """
    assert pre == post
