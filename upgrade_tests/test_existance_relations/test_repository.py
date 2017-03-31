"""Upgrade TestSuite for validating Satellite repositories existence and its
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('repository', 'name')
)
def test_positive_repositories_by_name(pre, post):
    """Test all repositories are existing after upgrade by names

    :id: 13811137-89f7-4dc7-b4b5-4aed91546bd5

    :expectedresults: All repositories should be retained post upgrade by names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('repository', 'product')
)
def test_positive_repositories_by_product(pre, post):
    """Test all repositories association with products are existing after
    upgrade

    :id: 24130f2e-4eef-4038-8ae6-14613c79e34a

    :expectedresults: All repositories association to its product should be
    retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('repository', 'content type')
)
def test_positive_repositories_by_url(pre, post):
    """Test all repositories urls are existing after upgrade

    :id: 0776a63f-863e-481d-a7a4-87e449029914

    :expectedresults: All repositories urls should be retained post upgrade
    """
    assert pre == post
