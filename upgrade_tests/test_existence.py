"""Upgrade TestSuite for validating Satellite entities existence and
associations post upgrade
"""
import unittest2 as unittest
from automation_tools.satellite6.upgrade.tests.existence import (
    compare_postupgrade
)


class OrganizationTestCase(unittest.TestCase):
    """Organizations Existence TestCases"""

    def test_positive_organizations_by_id(self):
        """Test all organizations are existing after upgrade by id's

        :id: d7eceba4-8076-4d46-aeaf-0679ea38586c

        :assert: All organizations should be retained post upgrade by id's
        """
        for pre, post in compare_postupgrade('organization', 'id'):
            with self.subTest(pre):
                self.assertEqual(pre, post)

    def test_positive_organizations_by_name(self):
        """Test all organizations are existing after upgrade by names

        :id: 361414af-fb7f-4b7b-bf5a-9b3d9cc82d03

        :assert: All organizations should be retained post upgrade by names
        """
        for pre, post in compare_postupgrade('organization', 'name'):
            with self.subTest(pre):
                self.assertEqual(pre, post)


class HostTestCase(unittest.TestCase):
    """Hosts Existence and Associations TestCases"""
    def test_positive_hosts_by_ip(self):
        """Test ip associations of all hosts post upgrade

        :id: 3b4f8315-8490-42bc-8afa-4a6c267558d7

        :assert: IP of each host should be associated to its respective host
            post upgrade
        """
        for pre, post in compare_postupgrade('host', 'ip'):
            with self.subTest(pre):
                self.assertEqual(pre, post)

    def test_positive_hosts_by_mac(self):
        """Test mac associations of all hosts post upgrade

        :id: 526af1dd-f2a1-4a66-a0d2-fe5c1ade165d

        :assert: MAC of each host should be associated to its respective host
            post upgrade
        """
        for pre, post in compare_postupgrade('host', 'mac'):
            with self.subTest(pre):
                self.assertEqual(pre, post)


class ContentViewTestCase(unittest.TestCase):
    """Content Views Existence and Associations TestCases"""
    def test_positive_cvs_by_repository_ids(self):
        """Test repository associations of all CVs post upgrade

        :id: c8da27df-7d96-44b7-ab2a-d23a56ea2b2b

        :assert: Repositories associations of each CV should be retained
            post upgrade
        """
        for pre, post in compare_postupgrade(
                'content-view', 'repository ids'):
            with self.subTest(pre):
                self.assertEqual(pre, post)

    def test_positive_cvs_by_label(self):
        """Test all CVs are existing after upgrade by their labels

        :id: 9a541a98-c4b1-417c-9bfd-c65aadd72afb

        :assert: All CVs should be retained post upgrade
        """
        for pre, post in compare_postupgrade('content-view', 'label'):
            with self.subTest(pre):
                self.assertEqual(pre, post)


class CapsuleTestCase(unittest.TestCase):
    """Capsule Existence and Associations TestCases"""
    def test_positive_capsules_by_name(self):
        """Test all capsules are existing after upgrade by their names

        :id: 774b8ae3-2c82-4224-afca-df70d5a22e9b

        :assert: All capsules should be retained post upgrade
        """
        for pre, post in compare_postupgrade('capsule', 'name'):
            with self.subTest(pre):
                self.assertEqual(pre, post)

    def test_positive_capsules_by_features(self):
        """Test all features of each capsule are existing post upgrade

        :id: 6d3b8f24-2d51-465c-8d01-5a159aa89f2f

        :assert: All features of all capsules should be retained post upgrade
        """
        for pre, post in compare_postupgrade('capsule', 'features'):
            with self.subTest(pre):
                self.assertEqual(pre, post)


class ActivationKeyTestCase(unittest.TestCase):
    """Activation Keys Existence and Associations TestCases"""
    def test_positive_aks_by_content_view(self):
        """Test CV association of all AKs post upgrade

        :id: 37804d7c-3667-45f3-8039-891908372ce7

        :assert: CV of all AKs should be retained post upgrade
        """
        for pre, post in compare_postupgrade(
                'activation-key', 'content view'):
            with self.subTest(pre):
                self.assertEqual(pre, post)

    def test_positive_aks_by_lc(self):
        """Test LC association of all AKs post upgrade

        :id: 16dc1ae8-f30d-45c3-8289-f0f0736ca603

        :assert: LC of all AKs should be retained post upgrade
        """
        for pre, post in compare_postupgrade(
                'activation-key', 'lifecycle environment'):
            with self.subTest(pre):
                self.assertEqual(pre, post)
