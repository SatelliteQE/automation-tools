"""Upgrade TestModule for validating Satellite AKs existence and
associations post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('activation-key', 'content view')
)
def test_positive_aks_by_content_view(pre, post):
    """Test CV association of all AKs post upgrade

    :id: 37804d7c-3667-45f3-8039-891908372ce7

    :assert: CV of all AKs should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('activation-key', 'lifecycle environment')
)
def test_positive_aks_by_lc(pre, post):
    """Test LC association of all AKs post upgrade

    :id: 16dc1ae8-f30d-45c3-8289-f0f0736ca603

    :assert: LC of all AKs should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('activation-key', 'name')
)
def test_positive_aks_by_name(pre, post):
    """Test AKs are existing by their name post upgrade

    :id: 31d079e2-a457-4b5a-b371-b0f70432bf1d

    :assert: AKs should be existing by their names post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('activation-key', 'host limit')
)
def test_positive_aks_by_host_limit(pre, post):
    """Test host limit associations of all AKs post upgrade

    :id: cee32f2a-d4f4-4cf8-91da-aaed426f1942

    :assert: Subscription consumptions by hosts of all AKs should be retained
    post upgrade
    """
    assert pre == post
