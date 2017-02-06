import os
import sys

from automation_tools import set_yum_debug_level, setup_capsule_firewall
from automation_tools.repository import enable_repos, disable_repos
from automation_tools.satellite6.capsule import generate_capsule_certs
from automation_tools.utils import distro_info, update_packages
from datetime import datetime
from fabric.api import env, execute, run
from automation_tools.satellite6.upgrade.tasks import (
    create_rhevm_instance,
    delete_rhevm_instance,
    sync_capsule_repos_to_upgrade
)
from automation_tools.satellite6.upgrade.tools import (
    copy_ssh_key, logger, reboot
)


logger = logger()


def satellite6_capsule_setup(sat_host, os_version):
    """Setup all per-requisites for user provided capsule or auto created
    capsule on rhevm for capsule upgrade.

    :param string sat_host: Satellite hostname to which the capsule registered
    :param string os_version: The OS version onto which the capsule installed
        e.g: rhel6, rhel7
    """
    # For User Defined Capsule
    if os.environ.get('CAPSULE_HOSTNAMES'):
        cap_hosts = os.environ.get('CAPSULE_HOSTNAMES')
        if not os.environ.get('CAPSULE_AK'):
            logger.warning('CAPSULE_AK environment variable is not defined !')
            sys.exit(1)
    # Else run upgrade on rhevm capsule
    else:
        # Get image name and Hostname from Jenkins environment
        missing_vars = [
            var for var in (
                'RHEV_CAP_IMAGE',
                'RHEV_CAP_HOST',
                'RHEV_CAPSULE_AK')
            if var not in os.environ]
        # Check if image name and Hostname in jenkins are set
        if missing_vars:
            logger.warning('The following environment variable(s) must be '
                           'set: {0}.'.format(', '.join(missing_vars)))
            sys.exit(1)
        cap_image = os.environ.get('RHEV_CAP_IMAGE')
        cap_hosts = os.environ.get('RHEV_CAP_HOST')
        cap_instance = 'upgrade_capsule_auto_{0}'.format(os_version)
        execute(delete_rhevm_instance, cap_instance)
        logger.info('Turning on Capsule Instance ....')
        execute(create_rhevm_instance, cap_instance, cap_image)
        execute(lambda: run('katello-service restart'), host=cap_hosts)
    env['capsule_hosts'] = cap_hosts
    if ',' in cap_hosts:
        cap_hosts = cap_hosts.split(',')
    else:
        cap_hosts = [cap_hosts]
    copy_ssh_key(sat_host, cap_hosts)
    execute(sync_capsule_repos_to_upgrade, cap_hosts, host=sat_host)
    for cap_host in cap_hosts:
        logger.info('Capsule {} is ready for Upgrade'.format(cap_host))
    return cap_hosts


def satellite6_capsule_upgrade(cap_host):
    """Upgrades capsule from existing version to latest version.

    :param string cap_host: Capsule hostname onto which the capsule upgrade
    will run

    The following environment variables affect this command:

    CAPSULE_URL
        Optional, defaults to available capsule version in CDN.
        URL for capsule of latest compose to upgrade.
    FROM_VERSION
        Capsule current version, to disable repos while upgrading.
        e.g '6.1','6.0'
    TO_VERSION
        Capsule version to upgrade to and enable repos while upgrading.
        e.g '6.1','6.2'

    """
    logger.highlight('\n========== CAPSULE UPGRADE =================\n')
    sat_host = env.get('satellite_host')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    set_yum_debug_level()
    setup_capsule_firewall()
    major_ver = distro_info()[1]
    # Re-register Capsule for 6.2
    # AS per host unification feature: if there is a host registered where the
    # Host and Content Host are in different organizations (e.g. host not in
    # org, and content host in one), the content host will be unregistered as
    # part of the upgrade process.
    if to_version == '6.2':
        ak_name = os.environ.get('CAPSULE_AK') if os.environ.get(
            'CAPSULE_AK') else os.environ.get('RHEV_CAPSULE_AK')
        run('subscription-manager register --org="Default_Organization" '
            '--activationkey={0} --force'.format(ak_name))
    disable_repos('rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
        major_ver, from_version))
    if from_version == '6.1' and major_ver == '6':
        enable_repos('rhel-server-rhscl-{0}-rpms'.format(major_ver))
    # Check what repos are set
    run('yum repolist')
    if from_version == '6.0':
        # Stop katello services, except mongod
        run('for i in qpidd pulp_workers pulp_celerybeat '
            'pulp_resource_manager httpd; do service $i stop; done')
    run('yum clean all', warn_only=True)
    logger.info('Updating system and capsule packages ... ')
    preyum_time = datetime.now().replace(microsecond=0)
    update_packages(quiet=False)
    postyum_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for capsule packages update - {}'.format(
        str(postyum_time-preyum_time)))
    if from_version == '6.0':
        run('yum install -y capsule-installer', warn_only=True)
        # Copy answer file from katello to capule installer
        run('cp /etc/katello-installer/answers.capsule-installer.yaml.rpmsave '
            '/etc/capsule-installer/answers.capsule-installer.yaml',
            warn_only=True)
    execute(
        generate_capsule_certs,
        cap_host,
        True,
        host=sat_host
    )
    # Copying the capsule cert to capsule
    execute(lambda: run("scp -o 'StrictHostKeyChecking no' {0}-certs.tar "
                        "root@{0}:/home/".format(cap_host)), host=sat_host)
    # Rebooting the system to see possible errors
    if os.environ.get('RHEV_CAP_HOST'):
        reboot(120)
        if from_version == '6.0':
            # Stopping the services again which started in reboot
            run('for i in qpidd pulp_workers pulp_celerybeat '
                'pulp_resource_manager httpd; do service $i stop; done')
    setup_capsule_firewall()
    preup_time = datetime.now().replace(microsecond=0)
    if to_version == '6.1':
        run('capsule-installer --upgrade --certs-tar '
            '/home/{0}-certs.tar'.format(cap_host))
    else:
        run('satellite-installer --scenario capsule --upgrade '
            '--certs-tar /home/{0}-certs.tar'.format(cap_host))
    postup_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for Capsule Upgrade - {}'.format(
        str(postup_time-preup_time)))
    run('katello-service status', warn_only=True)


def satellite6_capsule_zstream_upgrade():
    """Upgrades Capsule to its latest zStream version

    Note: For zstream upgrade both 'To' and 'From' version should be same

    FROM_VERSION
        Current satellite version which will be upgraded to latest version
    TO_VERSION
        Next satellite version to which satellite will be upgraded
    """
    logger.highlight('\n========== CAPSULE UPGRADE =================\n')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    if not from_version == to_version:
        logger.warning('zStream Upgrade on Capsule cannot be performed as '
                       'FROM and TO versions are not same!')
        sys.exit(1)
    major_ver = distro_info()[1]
    set_yum_debug_level()
    if os.environ.get('CAPSULE_URL'):
        disable_repos('rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
            major_ver, from_version))
    # Check what repos are set
    run('yum repolist')
    if from_version == '6.1' and major_ver == '6':
        enable_repos('rhel-server-rhscl-{0}-rpms'.format(major_ver))
    if from_version == '6.0':
        # Stop katello services, except mongod
        run('for i in qpidd pulp_workers pulp_celerybeat '
            'pulp_resource_manager httpd; do service $i stop; done')
    run('yum clean all', warn_only=True)
    logger.info('Updating system and capsule packages ... ')
    preyum_time = datetime.now().replace(microsecond=0)
    update_packages(quiet=False)
    postyum_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for capsule packages update - {}'.format(
        str(postyum_time-preyum_time)))
    # Rebooting the system to see possible errors
    if os.environ.get('RHEV_CAP_HOST'):
        reboot(120)
        if from_version == '6.0':
            # Stopping the services again which started in reboot
            run('for i in qpidd pulp_workers pulp_celerybeat '
                'pulp_resource_manager httpd; do service $i stop; done')
    setup_capsule_firewall()
    preup_time = datetime.now().replace(microsecond=0)
    if to_version == '6.0':
        run('katello-installer --upgrade')
    elif to_version == '6.1':
        run('capsule-installer --upgrade')
    else:
        run('satellite-installer --scenario capsule --upgrade ')
    postup_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for Capsule Upgrade - {}'.format(
        str(postup_time-preup_time)))
    run('katello-service status', warn_only=True)
