"""Upgrade TestSuite for validating Satellite smart variables existence
and associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('smart-variable', 'name')
)
def test_positive_smart_variables_by_name(pre, post):
    """Test all smart variables are existing after upgrade by names

    :id: d2543c28-135d-4e8f-8fe6-f510f74f51b9

    :expectedresults: All smart variables should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('smart-variable', 'default value')
)
def test_positive_smart_variables_by_default_value(pre, post):
    """Test all smart variables default values are retained after upgrade

    :id: c8337fbc-9c26-408a-a6ac-6f4886aabcdf

    :expectedresults: All smart variables default values should be retained
    post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('smart-variable', 'type')
)
def test_positive_smart_variables_by_type(pre, post):
    """Test all smart variables override check is retained after upgrade

    :id: 401e491c-bb54-4d2e-88a7-b6b6a9c033e3

    :expectedresults: All smart variables override check should be retained
    post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('smart-variable', 'puppet class')
)
def test_positive_smart_variables_by_puppet_class(pre, post):
    """Test all smart variables associations with its puppet class is retained
    after upgrade

    :id: 97721211-4cfe-4170-8e9b-5dd622e0ae81

    :expectedresults: All smart variables associations with puppet classes
    should be retained post upgrade
    """
    assert pre == post
