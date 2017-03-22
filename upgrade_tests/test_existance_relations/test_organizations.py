"""Upgrade TestSuite for validating Satellite Orgs existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('organization', 'id'))
def test_positive_organizations_by_id(pre, post):
    """Test all organizations are existing after upgrade by id's

    :id: d7eceba4-8076-4d46-aeaf-0679ea38586c

    :assert: All organizations should be retained post upgrade by id's
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('organization', 'name')
)
def test_positive_organizations_by_name(pre, post):
    """Test all organizations are existing after upgrade by names

    :id: 361414af-fb7f-4b7b-bf5a-9b3d9cc82d03

    :assert: All organizations should be retained post upgrade by names
    """
    assert pre == post
