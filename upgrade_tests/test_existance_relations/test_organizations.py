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


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('organization', 'label')
)
def test_positive_organizations_by_label(pre, post):
    """Test all organizations are existing after upgrade by labels

    :id: 6290b7eb-bf94-453c-9528-8b8de646eb7a

    :assert: All organizations should be retained post upgrade by labels
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('organization', 'description')
)
def test_positive_organizations_by_description(pre, post):
    """Test all organizations descriptions is retained post upgrade

    :id: fc8bb660-eb8f-4df0-a5be-82e51a21d32c

    :assert: All organizations descriptions should be retained post upgrade
    """
    assert pre == post
