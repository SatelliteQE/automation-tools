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
