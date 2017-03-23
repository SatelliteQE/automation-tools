"""Upgrade TestSuite for validating Satellite hostgroups existence and their
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('hostgroup', 'name'))
def test_positive_hostgroups_by_name(pre, post):
    """Test all hostgroups are existing post upgrade by their names

    :id: 61739c36-30da-4f52-957c-abb1d0e728c7

    :assert: All hostgroups should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('hostgroup', 'operating system')
)
def test_positive_hostgroups_by_os(pre, post):
    """Test OS associations of all hostgroups post upgrade

    :id: b2af5ad8-f7c8-49e6-9a9a-b31defb31e98

    :assert: OS associations of all hostgroups should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('hostgroup', 'environment')
)
def test_positive_hostgroups_by_lc(pre, post):
    """Test LC associations of all hostgroups post upgrade

    :id: 4a071358-689e-46f1-9641-fd5958d4e725

    :assert: LC associations of all hostgroups should be retained post upgrade
    """
    assert pre == post
