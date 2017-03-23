"""Upgrade TestSuite for validating Satellite roles existence post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('role', 'name'))
def test_positive_roles_by_name(pre, post):
    """Test all roles are existing post upgrade by their name

    :id: 0ee07ffb-ae2b-4b98-ad0a-5a0db568fc1e

    :assert: All roles should be retained post upgrade
    """
    assert pre == post
