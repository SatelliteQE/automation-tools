"""Upgrade TestSuite for validating Satellite settings existence post upgrade
"""
import pytest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


@pytest.mark.parametrize("pre,post", compare_postupgrade('settings', 'name'))
def test_positive_settings_by_name(pre, post):
    """Test all settings are existing post upgrade by their names

    :id: 802b547a-d9b1-4537-ba38-65d67985a94f

    :assert: All settings should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize("pre,post", compare_postupgrade('settings', 'value'))
def test_positive_settings_by_value(pre, post):
    """Test all settings value are preserved post upgrade

    :id: 5b60d8cb-aced-49e8-b4f5-42ea30892fce

    :assert: All settings values should be retained post upgrade
    """
    assert pre == post


@pytest.mark.parametrize(
    "pre,post",
    compare_postupgrade('settings', 'description')
)
def test_positive_settings_by_description(pre, post):
    """Test all settings descriptions are existing post upgrade

    :id: 3b5ccd81-cb0e-4bdd-a10f-972ad29f7ac6

    :assert: All settings descriptions should be retained post upgrade
    """
    assert pre == post
