"""Upgrade TestSuite for validating Satellite products existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('product', 'name')
)
def test_positive_products_by_name(pre, post):
    """Test all products are existing after upgrade by names

    :id: 3dea1ee4-ed57-4341-957a-d9b1813ff4db

    :expectedresults: All products should be retained post upgrade by names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('product', 'repositories')
)
def test_positive_products_by_repositories(pre, post):
    """Test all products association with their repositories are existing after
    upgrade

    :id: cb3b838b-d69d-4de9-9ebb-bbc6143ecdbf

    :expectedresults: Repositories of all products should be retained post
    upgrade
    """
    assert pre == post
