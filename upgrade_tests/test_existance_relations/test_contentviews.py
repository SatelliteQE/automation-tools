"""Upgrade TestSuite for validating Satellite CVs existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('content-view', 'repository ids')
)
def test_positive_cvs_by_repository_ids(pre, post):
    """Test repository associations of all CVs post upgrade

    :id: c8da27df-7d96-44b7-ab2a-d23a56ea2b2b

    :assert: Repositories associations of each CV should be retained
        post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('content-view', 'label')
)
def test_positive_cvs_by_label(pre, post):
    """Test all CVs are existing after upgrade by their labels

    :id: 9a541a98-c4b1-417c-9bfd-c65aadd72afb

    :assert: All CVs should be retained post upgrade
    """
    assert pre == post
