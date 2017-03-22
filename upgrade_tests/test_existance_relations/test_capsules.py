"""Upgrade TestSuite for validating Satellite capsules existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('capsule', 'features')
)
def test_positive_capsules_by_features(pre, post):
    """Test all features of each capsule are existing post upgrade

    :id: 6d3b8f24-2d51-465c-8d01-5a159aa89f2f

    :assert: All features of all capsules should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('capsule', 'name')
)
def test_positive_capsules_by_name(pre, post):
    """Test all capsules are existing after upgrade by their names

    :id: 774b8ae3-2c82-4224-afca-df70d5a22e9b

    :assert: All capsules should be retained post upgrade
    """
    assert pre == post
