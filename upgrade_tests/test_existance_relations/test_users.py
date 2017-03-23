"""Upgrade TestSuite for validating Satellite users existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('user', 'name'))
def test_positive_users_by_name(pre, post):
    """Test all users are existing post upgrade by their name

    :id: 1accdb79-7dd6-4cf7-904a-b179e108ba2d

    :assert: All users should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('user', 'login'))
def test_positive_users_by_login(pre, post):
    """Test all users login name are existing post upgrade

    :id: 1b8cba29-38e7-4d65-a8b2-4f5abab511dd

    :assert: All users login name should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('user', 'email'))
def test_positive_users_by_email(pre, post):
    """Test all users email are existing post upgrade

    :id: 45d267e9-a714-4fc1-952d-fa2ddd1e8231

    :assert: All users email should be retained post upgrade
    """
    assert pre == post
