"""Upgrade TestSuite for validating gpg keys existence post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('gpg', 'name')
)
def test_positive_gpg_keys_by_name(pre, post):
    """Test all gpg keys are existing after upgrade by names

    :id: 23b96c3e-2510-4886-91e6-9864f0d5e3e5

    :expectedresults: All gpg keys should be retained post upgrade by names
    """
    assert pre == post
