"""Upgrade TestSuite for validating Satellite subnets existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('subnet', 'name'))
def test_positive_subnets_by_name(pre, post):
    """Test all subnets are existing post upgrade by their name

    :id: 07b32bf4-2205-4b9c-8af0-69c801058785

    :assert: All subnets should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('subnet', 'network'))
def test_positive_subnets_by_network(pre, post):
    """Test all subnets network ip's are existing post upgrade

    :id: 72d77821-15cd-4803-a7bd-623aeb7c692e

    :assert: All subnets network ip's should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('subnet', 'mask'))
def test_positive_subnets_by_mask(pre, post):
    """Test all subnets masks are existing post upgrade

    :id: 18a6bbb1-00bf-4b3f-ada3-b7c3b9341460

    :assert: All subnets masks should be retained post upgrade
    """
    assert pre == post
