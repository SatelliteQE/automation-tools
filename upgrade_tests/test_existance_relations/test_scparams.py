"""Upgrade TestSuite for validating Satellite smart class parameters
 existence and associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sc-param', 'parameter')
)
def test_positive_smart_params_by_name(pre, post):
    """Test all smart parameters are existing after upgrade by names

    :id: 44113fb7-eab2-439b-986c-6110a1c15d54

    :expectedresults: All smart parameters should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sc-param', 'default value')
)
def test_positive_smart_params_by_default_value(pre, post):
    """Test all smart parameters default values are retained after upgrade

    :id: 35a94fb5-5601-4b85-b23a-dd3ccb945bd6

    :expectedresults: All smart parameters default values should be retained
    post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sc-param', 'override')
)
def test_positive_smart_params_by_override(pre, post):
    """Test all smart parameters override check is retained after upgrade

    :id: 9f045338-8a79-43b1-a22c-45e79e8dbc56

    :expectedresults: All smart parameters override check should be retained
    post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sc-param', 'puppet class')
)
def test_positive_smart_params_by_puppet_class(pre, post):
    """Test all smart parameters associations with its puppet class is retained
    after upgrade

    :id: 86714406-afcf-45a8-8db9-07ea03251cfa

    :expectedresults: All smart parameters associations with puppet classes
    should be retained post upgrade
    """
    assert pre == post
