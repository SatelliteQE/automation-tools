import os
import time

from automation_tools.satellite6 import hammer
from automation_tools.satellite6.upgrade.tasks import (
    docker_execute_command,
    refresh_subscriptions_on_docker_clients
)
from automation_tools.satellite6.upgrade.tests.utils import (
    create_dict,
    dockerize,
    get_entity_data,
    get_latest_repo_version,
    get_satellite_host,
    rpm1,
    rpm2

)
from fabric.api import execute, run
from fauxfactory import gen_alpha
from unittest2.case import TestCase
from upgrade_tests import post_upgrade, pre_upgrade


class ScenarioBug1429201(TestCase):
    """This Class will server as a whole scenario with pre-upgarde and
    post-upgrade test-case
    """
    prd_name = gen_alpha()
    repo_name = gen_alpha()
    lc_name = gen_alpha()
    ak_name = gen_alpha()
    cv_name = gen_alpha()
    docker_vm = os.environ.get('DOCKER_VM')
    org_id = 1
    sat_host = get_satellite_host()
    file_path = '/var/www/html/pub/custom_repo/'
    custom_repo = 'https://' + sat_host + '/pub/custom_repo/'
    _, rpm1_name = os.path.split(rpm1)
    _, rpm2_name = os.path.split(rpm2)

    def setUp(self):
        hammer.set_hammer_config(host=self.sat_host)

    @pre_upgrade
    def test_pre_user_scenario_bug_1429201(self):
        """This is pre-upgrade scenario test to verify if we can create a
        custom repository and consume it via client

        :steps:
            1. Create repository RepoFoo that you will later add to your
               Satellite. This repository should contain PackageFoo-1.0.rpm
            2. Install satellite 6.1
            3. Create custom product ProductFoo pointing to repository RepoFoo
            4. Sync RepoFoo
            5. Create content view CVFoo
            6. Add RepoFoo to CVFoo
            7. Publish version 1 of CVFoo

        :expectedresults: The client and product is created successfully
        """
        try:
            run('rm -rf {0}'.format(self.file_path))
            run('mkdir {0}'.format(self.file_path))
        except OSError:
            run('mkdir /var/www/html/pub/custom_repo')
        run('wget {0} -P {1}'.format(rpm1, self.file_path))
        run('createrepo --database {0}'.format(self.file_path))
        # End to End product + ak association
        print hammer.hammer_product_create(self.prd_name, self.org_id)
        print hammer.hammer_repository_create(self.repo_name,
                                              self.org_id,
                                              self.prd_name,
                                              self.custom_repo
                                              )
        print hammer.hammer_create_lifecycle_env(self.lc_name, self.org_id, 1)
        print hammer.hammer_repository_synchronize(self.repo_name,
                                                   self.org_id,
                                                   self.prd_name
                                                   )
        print hammer.hammer_content_view_create(self.cv_name, self.org_id)
        print hammer.hammer_content_view_add_repository(self.cv_name,
                                                        self.org_id,
                                                        self.prd_name,
                                                        self.repo_name
                                                        )
        print hammer.hammer_content_view_publish(self.cv_name, self.org_id)
        latest_repo_version = get_latest_repo_version(self.cv_name)
        lifecycle_id = hammer.hammer_get_entity_id(
                        'lifecycle-environment',
                        self.lc_name,
                        self.org_id
                        )
        print hammer.hammer_content_view_promote_version(self.cv_name,
                                                         latest_repo_version,
                                                         lifecycle_id,
                                                         self.org_id
                                                         )
        print hammer.hammer_activation_key_create(self.ak_name,
                                                  self.org_id,
                                                  self.cv_name,
                                                  self.lc_name
                                                  )
        print hammer.hammer_activation_key_add_subscription(self.ak_name,
                                                            self.org_id,
                                                            self.prd_name
                                                            )
        time.sleep(5)
        # Creating vm and subscribing to AK
        container_ids = dockerize(self.ak_name)
        print container_ids.values()[0]
        time.sleep(30)  # Subscription manager needs time to register
        result = execute(
            docker_execute_command,
            container_ids.values()[0],
            'yum list {0} | grep {0}'.format(self.rpm1_name.split('-')[0]),
            host=self.docker_vm)
        # Info on created entities to assert the test case using hammer info
        prd_info = hammer.hammer_info_via_name('product', self.prd_name,
                                               self.org_id
                                               )
        get_name = hammer.get_attribute_value(prd_info, self.prd_name, 'name')
        self.assertEqual(self.prd_name, get_name)
        self.assertIsNotNone(container_ids)
        self.assertIn(self.repo_name, result.values()[0])
        global_dict = {self.__class__.__name__: {
            'prd_name': self.prd_name,
            'ak_name': self.ak_name,
            'repo_name': self.repo_name,
            'container_ids': container_ids
        }
        }
        create_dict(global_dict)

    @post_upgrade
    def test_post_user_scenario_bug_1429201(self):
        """This is post-upgrade scenario test to verify if we can alter the
        created custom repository and satellite will be able to sync back
        the repo

        :steps:
            1. Remove PackageFoo-1.0.rpm from RepoFoo
            2. Add PackageFoo-2.0.rpm to RepoFoo
            3. Sync RepoFoo
            4. Publish version 2 of CVFoo
            5. Delete version 1 of CVFoo
            6. run /etc/cron.weekly/katello-remove-orphans
            7. Subscribe ClientA to CVFoo
            8. Try to install PackageFoo-1.0.rpm on ClientA
            9. Notice that yum thinks it's there based on the repo metadata
               but then fails to download it with 404
            10. Try to install PackageFoo-2.0.rpm

        :expectedresults: The clients is present after upgrade and deleted
        rpm is unable to be fetched, while new rpm is pulled and installed
        on client

        """
        entity_data = get_entity_data(self.__class__.__name__)
        run('wget {0} -P {1}'.format(rpm2, self.file_path))
        run('rm -rf {0}'.format(self.file_path + self.rpm1_name))
        run('createrepo --update {0}'.format(self.file_path))
        # get entities from pickle
        pkcl_ak_name = entity_data['ak_name']
        container_ids = entity_data['container_ids']
        repo_name = entity_data['repo_name']
        prd_name = entity_data['prd_name']
        cv_name, lc_name = hammer.hammer_determine_cv_and_env_from_ak(
                            pkcl_ak_name,
                            self.org_id
                            )
        ak_info = hammer.hammer_info_via_name(
                    'activation-key', pkcl_ak_name,
                    self.org_id)
        print hammer.hammer_repository_synchronize(repo_name, self.org_id,
                                                   prd_name)
        print hammer.hammer_content_view_publish(cv_name, self.org_id)
        latest_repo_version = get_latest_repo_version(cv_name)
        lifecycle_id = hammer.hammer_get_entity_id(
                        'lifecycle-environment',
                        lc_name,
                        self.org_id)
        print hammer.hammer_content_view_promote_version(cv_name,
                                                         latest_repo_version,
                                                         lifecycle_id,
                                                         self.org_id)
        print hammer.hammer_remove_cv_version(latest_repo_version, cv_name,
                                              self.org_id)
        run('/etc/cron.weekly/katello-remove-orphans')
        execute(refresh_subscriptions_on_docker_clients,
                container_ids.values(), host=self.docker_vm)
        time.sleep(30)  # Subscription manager needs time to register
        result_fail = execute(
            docker_execute_command,
            container_ids.values()[0],
            'yum list {0} | grep {0}'.format(self.rpm1_name.split('-')[0]),
            quiet=True,
            host=self.docker_vm)  # should be error
        result_pass = execute(
            docker_execute_command,
            container_ids.values()[0],
            'yum install -y {0}'.format(self.rpm2_name.split('-')[0]),
            host=self.docker_vm)  # should be successful
        self.assertEqual(pkcl_ak_name,
                         hammer.get_attribute_value(ak_info, pkcl_ak_name,
                                                    'name'))
        self.assertIsNotNone(container_ids)
        self.assertIn('Error', result_fail.values()[0])
        self.assertIn('Complete', result_pass.values()[0])
