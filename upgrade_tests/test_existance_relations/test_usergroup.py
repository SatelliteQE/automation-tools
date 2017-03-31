"""Upgrade TestSuite for validating Satellite auser groups existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('user-group', 'name')
)
def test_positive_usergroups_by_name(pre, post):
    """Test all usergroups are existing after upgrade by names

    :id: 62e8bbca-25f5-403c-b868-7f0bc11ff341

    :expectedresults: All user groups should be retained post upgrade by names
    """
    assert pre == post
