"""Upgrade TestSuite for validating Satellite host discovery existence and
its relations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'name')
)
def test_positive_discovery_by_name(pre, post):
    """Test all architectures are existing after upgrade by names

    :id: 2322766f-0731-4e80-bf54-d48a8756406d

    :expectedresults: All architectures should be retained post upgrade by
    names
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'mac')
)
def test_positive_discovery_by_mac(pre, post):
    """Test discovered hosts mac is retained after upgrade

    :id: 348a11f1-e7c2-4ff5-b36c-c79626ff2142

    :expectedresults: All discovered hosts mac should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'cpus')
)
def test_positive_discovery_by_cpus(pre, post):
    """Test discovered hosts cpus are retained after upgrade

    :id: 733663f6-4bee-4e0d-b4ed-35ac2e0e6370

    :expectedresults: All discovered hosts cpus should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'memory')
)
def test_positive_discovery_by_memory(pre, post):
    """Test discovered hosts memory allocation is retained after upgrade

    :id: 91d2c395-d788-45c8-b722-051fbed18d38

    :expectedresults: All discovered hosts memory allocation should be retained
    post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'disk count')
)
def test_positive_discovery_by_disc_counts(pre, post):
    """Test discovered hosts disc counts are retained after upgrade

    :id: ddb9c37c-4287-4419-b890-8a7891a333f0

    :expectedresults: All discovered hosts disk counts should be retained post
     upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'disks size')
)
def test_positive_discovery_by_disc_size(pre, post):
    """Test discovered hosts disc size are retained after upgrade

    :id: ad71e779-cded-4ba7-aaf2-ff0d138b3613

    :expectedresults: All discovered hosts disk size should be retained post
     upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('discovery', 'subnet')
)
def test_positive_discovery_by_subnet(pre, post):
    """Test discovered hosts subnet is retained after upgrade

    :id: c5218155-95a4-4a90-b853-76f843bb07c0

    :expectedresults: All discovered hosts subnet should be retained post
     upgrade
    """
    assert pre == post
