"""Upgrade TestSuite for validating Satellite sync plans existence and its
association post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sync-plan', 'name')
)
def test_positive_syncplans_by_name(pre, post):
    """Test all sync plans are existing after upgrade by names

    :id: 8030bff2-455e-4b1a-8b62-0596465ef2da

    :expectedresults: All sync plans should be retained post upgrade by names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sync-plan', 'start date')
)
def test_positive_syncplans_by_start_date(pre, post):
    """Test all sync plans start date is retained after upgrade

    :id: 8106ddf2-701c-4c58-8246-b0122195fa5d

    :expectedresults: All sync plans start date should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sync-plan', 'interval')
)
def test_positive_syncplans_by_interval(pre, post):
    """Test all sync plans interval time is retained after upgrade

    :id: 058eeba9-9a4d-44c5-a759-48c3199b70f0

    :expectedresults: All sync plans interval time should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('sync-plan', 'enabled')
)
def test_positive_syncplans_by_enablement(pre, post):
    """Test all sync plans enablement and disablement is retained after upgrade

    :id: a90e8c93-74b5-49f8-9c08-4fba7903635c

    :expectedresults: All sync plans enablement and disablement should be
    retained post upgrade
    """
    assert pre == post
