"""Upgrade TestSuite for validating Satellite discovery rules existence abd
its associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'name')
)
def test_positive_discovery_rules_by_name(pre, post):
    """Test all discovery rules are existing after upgrade by name

    :id: 0d7e8920-5717-4196-af8a-977cfba33184

    :expectedresults: All discovery rules should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'priority')
)
def test_positive_discovery_rules_by_priority(pre, post):
    """Test all discovery rules priorities are existing after upgrade

    :id: f2a1c6e6-d025-463c-a837-4f4657106f1e

    :expectedresults: All discovery rules priorities should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'search')
)
def test_positive_discovery_rules_by_search(pre, post):
    """Test all discovery rules search are existing after upgrade

    :id: ef1944c4-62f6-447e-90d9-f8ed95eb35de

    :expectedresults: All discovery rules search should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'host group')
)
def test_positive_discovery_rules_by_hostgroup(pre, post):
    """Test all discovery rules hostgroup associations are existing after
    upgrade

    :id: da605ae6-cdf8-49f9-87f6-c1cdfc411f90

    :expectedresults: All discovery rules hostgroups should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'hosts limit')
)
def test_positive_discovery_rules_by_hostslimit(pre, post):
    """Test all discovery rules hosts limit are retained after upgrade

    :id: a9c59324-85eb-4295-8f2d-6f2e783a63dd

    :expectedresults: All discovery rules hosts limit should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery_rule', 'enabled')
)
def test_positive_discovery_rules_by_enablement(pre, post):
    """Test all discovery rules enablement and disablement is existing after
    upgrade

    :id: 7b71be69-1c60-43e8-bbfb-938565ef8eee

    :expectedresults: All discovery rules enablement and disablement should be
    retained post upgrade
    """
    assert pre == post
