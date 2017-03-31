"""Upgrade TestSuite for validating Satellite content hosts existence
post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('content-host', 'name')
)
def test_positive_contenthosts_by_name(pre, post):
    """Test all content hosts are existing after upgrade by names

    :id: aa92463b-e693-4c30-b0cb-e2cafdab1c7f

    :expectedresults: All content hosts should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('content-host', 'installable errata')
)
def test_positive_installable_erratas_by_name(pre, post):
    """Test all content hosts installable erratas are existing after upgrade

    :id: bc40b921-c39b-4cd0-9816-87b53d1af352

    :expectedresults: All chosts installable erratas should be retained post
    upgrade
    """
    assert pre == post
