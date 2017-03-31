"""Upgrade TestSuite for validating Satellite lifecycle environments existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('lifecycle-environment', 'name')
)
def test_positive_lifecycle_envs_by_name(pre, post):
    """Test all lifecycle envs are existing after upgrade by names

    :id: 4bb9c13a-b573-4f03-b2b3-65592e275eb1

    :expectedresults: All lifecycle envs should be retained post upgrade by
    names
    """
    assert pre == post
