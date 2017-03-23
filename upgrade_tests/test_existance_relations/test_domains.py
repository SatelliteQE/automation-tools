"""Upgrade TestSuite for validating Satellite domains existence post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('domain', 'name'))
def test_positive_domains_by_name(pre, post):
    """Test all domains are existing post upgrade by their names

    :id: 0f00b7c4-da85-437d-beae-19a0c50ae9d0

    :assert: All domains should be retained post upgrade
    """
    assert pre == post
