"""Upgrade TestSuite for validating puppet environment existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('environment', 'name')
)
def test_positive_puppet_envs_by_name(pre, post):
    """Test all puppet envs are existing after upgrade by names

    :id: d144094d-48fd-450b-8570-bd53758e090f

    :expectedresults: All puppet envs should be retained post upgrade by names
    """
    assert pre == post
