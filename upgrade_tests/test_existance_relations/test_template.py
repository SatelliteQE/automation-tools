"""Upgrade TestSuite for validating Satellite provisioning templates existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('template', 'name')
)
def test_positive_templates_by_name(pre, post):
    """Test all templates are existing after upgrade by names

    :id: fce33637-8e7b-4ccf-a9fb-47f0e0607f83

    :expectedresults: All templates should be retained post upgrade by names
    """
    assert pre == post
