"""Upgrade TestSuite for validating Satellite architectures existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('architecture', 'name')
)
def test_positive_architectures_by_name(pre, post):
    """Test all architectures are existing after upgrade by names

    :id: eb6d3728-6b0b-4cb7-888e-8d64a46e7beb

    :expectedresults: All architectures should be retained post upgrade by
    names
    """
    assert pre == post
