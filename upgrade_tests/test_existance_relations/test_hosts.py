"""Upgrade TestSuite for validating Satellite hosts existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('host', 'ip'))
def test_positive_hosts_by_ip(pre, post):
    """Test ip associations of all hosts post upgrade

    :id: 3b4f8315-8490-42bc-8afa-4a6c267558d7

    :assert: IP of each host should be associated to its respective host
        post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('host', 'mac'))
def test_positive_hosts_by_mac(pre, post):
    """Test mac associations of all hosts post upgrade

    :id: 526af1dd-f2a1-4a66-a0d2-fe5c1ade165d

    :assert: MAC of each host should be associated to its respective host
        post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('host', 'host group'))
def test_positive_hosts_by_hostgroup(pre, post):
    """Test hostgroup associations of all hosts post upgrade

    :id: 75d861ad-d8b5-4051-a584-b06ac63fd444

    :assert: HostGroup of each host should be associated to its respective host
        post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('host', 'operating system')
)
def test_positive_hosts_by_operating_system(pre, post):
    """Test OS associations of all hosts post upgrade

    :id: 13c93f4b-0a46-4c74-aefa-136484bd8999

    :assert: OS of each host should be associated to its respective host
        post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('host', 'name')
)
def test_positive_hosts_by_name(pre, post):
    """Test all hosts are retained post upgrade by their name

    :id: 2421fe0d-370d-4191-af36-1565f7c088bd

    :assert: All hosts should be retained post upgrade by their names
    """
    assert pre == post
