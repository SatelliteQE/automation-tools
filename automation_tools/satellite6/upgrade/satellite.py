import os
import sys

from automation_tools.satellite6.upgrade.tests.existence import set_datastore
from automation_tools.satellite6.upgrade.tools import host_pings, reboot
from automation_tools import (
    enable_ostree,
    set_yum_debug_level,
    setup_satellite_firewall,
    subscribe,
    install_prerequisites
)
from automation_tools.satellite6.hammer import hammer, set_hammer_config
from automation_tools.repository import enable_repos, disable_repos
from automation_tools.utils import distro_info, update_packages
from datetime import datetime
from fabric.api import env, execute, put, run
from automation_tools.satellite6.upgrade.tasks import (
    create_rhevm_instance,
    delete_rhevm_instance
)
from automation_tools.satellite6.upgrade.tools import logger
if sys.version_info[0] is 2:
    from StringIO import StringIO  # (import-error) pylint:disable=F0401
else:  # pylint:disable=F0401,E0611
    from io import StringIO

logger = logger()


def satellite6_setup(os_version):
    """Sets up required things on upgrade running machine and on Satellite to
    perform satellite upgrade later

    :param string os_version: The OS version onto which the satellite installed
        e.g: rhel6, rhel7
    """
    # If Personal Satellite Hostname provided
    if os.environ.get('SATELLITE_HOSTNAME'):
        sat_host = os.environ.get('SATELLITE_HOSTNAME')
    # Else run upgrade on rhevm satellite
    else:
        # Get image name and Hostname from Jenkins environment
        missing_vars = [
            var for var in ('RHEV_SAT_IMAGE', 'RHEV_SAT_HOST')
            if var not in os.environ]
        # Check if image name and Hostname in jenkins are set
        if missing_vars:
            logger.warning('The following environment variable(s) must be set '
                           'in jenkin environment: {0}.'.format(
                                ', '.join(missing_vars)))
            sys.exit(1)
        sat_image = os.environ.get('RHEV_SAT_IMAGE')
        sat_host = os.environ.get('RHEV_SAT_HOST')
        sat_instance = 'upgrade_satellite_auto_{0}'.format(os_version)
        execute(delete_rhevm_instance, sat_instance)
        execute(create_rhevm_instance, sat_instance, sat_image)
        if not host_pings(sat_host):
            sys.exit(1)
        # start's/enables/install's ntp
        # Check that hostname and localhost resolve correctly
        execute(install_prerequisites, host=sat_host)
        # Subscribe the instance to CDN
        execute(subscribe, host=sat_host)
        execute(lambda: run('katello-service restart'), host=sat_host)
    # Set satellite hostname in fabric environment
    env['satellite_host'] = sat_host
    logger.info('Satellite {} is ready for Upgrade!'.format(sat_host))
    if os.environ.get('RUN_EXISTANCE_TESTS', 'false').lower() == 'true':
        logger.info('Setting up preupgrade datastore for existance tests')
        set_datastore('preupgrade')
    return sat_host


def satellite6_upgrade():
    """Upgrades satellite from old version to latest version.

    The following environment variables affect this command:

    BASE_URL
        Optional, defaults to available satellite version in CDN.
        URL for the compose repository
    TO_VERSION
        Satellite version to upgrade to and enable repos while upgrading.
        e.g '6.1','6.2'
    """
    logger.highlight('\n========== SATELLITE UPGRADE =================\n')
    to_version = os.environ.get('TO_VERSION')
    rhev_sat_host = os.environ.get('RHEV_SAT_HOST')
    base_url = os.environ.get('BASE_URL')
    if to_version not in ['6.1', '6.2']:
        logger.warning('Wrong Satellite Version Provided to upgrade to. '
                       'Provide one of 6.1, 6.2')
        sys.exit(1)
    # Setting yum stdout log level to be less verbose
    set_yum_debug_level()
    setup_satellite_firewall()
    run('rm -rf /etc/yum.repos.d/rhel-{optional,released}.repo')
    logger.info('Updating system packages ... ')
    update_packages(quiet=True)
    # Rebooting the system to see possible errors
    if rhev_sat_host:
        reboot(160)
    # Setting Satellite to_version Repos
    major_ver = distro_info()[1]
    # Following disables the old satellite repo and extra repos enabled
    # during subscribe e.g Load balancer Repo
    disable_repos('*', silent=True)
    enable_repos('rhel-{0}-server-rpms'.format(major_ver))
    enable_repos('rhel-server-rhscl-{0}-rpms'.format(major_ver))
    # If CDN upgrade then enable satellite latest version repo
    if base_url is None:
        enable_repos('rhel-{0}-server-satellite-{1}-rpms'.format(
            major_ver, to_version))
        # Remove old custom sat repo
        for fname in os.listdir('/etc/yum.repos.d/'):
            if 'sat' in fname.lower():
                os.remove('/etc/yum.repos.d/{}'.format(fname))
    # Else, consider this as Downstream upgrade
    else:
        # Add Sat6 repo from latest compose
        satellite_repo = StringIO()
        satellite_repo.write('[sat6]\n')
        satellite_repo.write('name=satellite 6\n')
        satellite_repo.write('baseurl={0}\n'.format(base_url))
        satellite_repo.write('enabled=1\n')
        satellite_repo.write('gpgcheck=0\n')
        put(local_path=satellite_repo,
            remote_path='/etc/yum.repos.d/sat6.repo')
        satellite_repo.close()
    # Check what repos are set
    run('yum repolist')
    # Stop katello services, except mongod
    run('katello-service stop')
    if to_version == '6.1':
        run('service-wait mongod start')
    run('yum clean all', warn_only=True)
    # Updating the packages again after setting sat6 repo
    logger.info('Updating satellite packages ... ')
    preyum_time = datetime.now().replace(microsecond=0)
    update_packages(quiet=False)
    postyum_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for satellite packages update - {}'.format(
        str(postyum_time-preyum_time)))
    # Rebooting the system again for possible errors
    # Only for RHEV based satellite and not for personal one
    if rhev_sat_host:
        reboot(160)
        if to_version == '6.1':
            # Stop the service again which started in restart
            # This step is not required with 6.2 upgrade as installer itself
            # stop all the services before upgrade
            run('katello-service stop')
            run('service-wait mongod start')
    # Running Upgrade
    preup_time = datetime.now().replace(microsecond=0)
    if to_version == '6.1':
        run('katello-installer --upgrade')
    else:
        run('satellite-installer --scenario satellite --upgrade')
    postup_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for Satellite Upgrade - {}'.format(
        str(postup_time-preup_time)))
    # Test the Upgrade is successful
    set_hammer_config()
    hammer('ping')
    run('katello-service status', warn_only=True)
    # Enable ostree feature only for rhel7 and sat6.2
    if to_version == '6.2' and major_ver == '7':
        enable_ostree(sat_version='6.2')
    if os.environ.get('RUN_EXISTANCE_TESTS', 'false').lower() == 'true':
        logger.info('Setting up postupgrade datastore for existance tests..')
        set_datastore('postupgrade')


def satellite6_zstream_upgrade():
    """Upgrades Satellite Server to its latest zStream version

    Note: For zstream upgrade both 'To' and 'From' version should be same

    FROM_VERSION
        Current satellite version which will be upgraded to latest version
    TO_VERSION
        Next satellite version to which satellite will be upgraded
    """
    logger.highlight('\n========== SATELLITE UPGRADE =================\n')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    if not from_version == to_version:
        logger.warning('zStream Upgrade on Satellite cannot be performed as '
                       'FROM and TO versions are not same!')
        sys.exit(1)
    base_url = os.environ.get('BASE_URL')
    # Setting yum stdout log level to be less verbose
    set_yum_debug_level()
    setup_satellite_firewall()
    major_ver = distro_info()[1]
    # Following disables the old satellite repo and extra repos enabled
    # during subscribe e.g Load balancer Repo
    disable_repos('*', silent=True)
    enable_repos('rhel-{0}-server-rpms'.format(major_ver))
    enable_repos('rhel-server-rhscl-{0}-rpms'.format(major_ver))
    # If CDN upgrade then enable satellite latest version repo
    if base_url is None:
        enable_repos('rhel-{0}-server-satellite-{1}-rpms'.format(
            major_ver, to_version))
        # Remove old custom sat repo
        for fname in os.listdir('/etc/yum.repos.d/'):
            if 'sat' in fname.lower():
                os.remove('/etc/yum.repos.d/{}'.format(fname))
    # Else, consider this as Downstream upgrade
    else:
        # Add Sat6 repo from latest compose
        satellite_repo = StringIO()
        satellite_repo.write('[sat6]\n')
        satellite_repo.write('name=satellite 6\n')
        satellite_repo.write('baseurl={0}\n'.format(base_url))
        satellite_repo.write('enabled=1\n')
        satellite_repo.write('gpgcheck=0\n')
        put(local_path=satellite_repo,
            remote_path='/etc/yum.repos.d/sat6.repo')
        satellite_repo.close()
    # Check what repos are set
    run('yum repolist')
    # Stop katello services, except mongod
    run('katello-service stop')
    if to_version == '6.1':
        run('service-wait mongod start')
    run('yum clean all', warn_only=True)
    # Updating the packages again after setting sat6 repo
    logger.info('Updating system and satellite packages... ')
    preyum_time = datetime.now().replace(microsecond=0)
    update_packages(quiet=False)
    postyum_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for system and satellite packages update - '
                     '{}'.format(str(postyum_time-preyum_time)))
    # Rebooting the system to check the possible issues if kernal is updated
    if os.environ.get('RHEV_SAT_HOST'):
        reboot(120)
        if to_version == '6.1':
            # Stop the service again which started in restart
            # This step is not required with 6.2 upgrade as installer itself
            # stop all the services before upgrade
            run('katello-service stop')
            run('service-wait mongod start')
    # Running Upgrade
    preup_time = datetime.now().replace(microsecond=0)
    if to_version == '6.1':
        run('katello-installer --upgrade')
    else:
        run('satellite-installer --scenario satellite --upgrade')
    postup_time = datetime.now().replace(microsecond=0)
    logger.highlight('Time taken for Satellite Upgrade - {}'.format(
        str(postup_time-preup_time)))
    # Test the Upgrade is successful
    set_hammer_config()
    hammer('ping')
    run('katello-service status', warn_only=True)
    if os.environ.get('RUN_EXISTANCE_TESTS', 'false').lower() == 'true':
        logger.info('Setting up postupgrade datastore for existance tests')
        set_datastore('postupgrade')
