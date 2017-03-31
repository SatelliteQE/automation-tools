"""Upgrade TestSuite for validating Satellite subscriptions existence post
upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'name')
)
def test_positive_subscriptions_by_name(pre, post):
    """Test all subscriptions are existing after upgrade by names

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'uuid')
)
def test_positive_subscriptions_by_uuid(pre, post):
    """Test all subscriptions uuids are existing after upgrade

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions uuids should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'support')
)
def test_positive_subscriptions_by_support(pre, post):
    """Test all subscriptions support status is retained after upgrade

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions support status should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'quantity')
)
def test_positive_subscriptions_by_quantity(pre, post):
    """Test all subscriptions quantities are retained after upgrade

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions quantities should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'consumed')
)
def test_positive_subscriptions_by_consumed(pre, post):
    """Test all subscriptions consumed status is retained after upgrade

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions consumed status should be retained post
    upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('subscription', 'end date')
)
def test_positive_subscriptions_by_end_date(pre, post):
    """Test all subscriptions end date status is retained after upgrade

    :id: 535d6529-27cb-4c6f-959e-6d0684e77aa6

    :expectedresults: All subscriptions end date status should be retained post
    upgrade
    """
    assert pre == post
