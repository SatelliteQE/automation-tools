"""A set of upgrade tasks for upgrading Satellite and Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import os
import sys
import time
from tasks import (
    create_rhevm_instance, delete_rhevm_instance,
    sync_capsule_tools_repos_to_upgrade
)
from tools import copy_ssh_key, host_pings, reboot
from automation_tools import (
    foreman_debug,
    set_yum_debug_level,
    setup_satellite_firewall,
    setup_capsule_firewall,
    subscribe,
)
from automation_tools.repository import enable_repos, disable_repos
from automation_tools.satellite6.capsule import generate_capsule_certs
from automation_tools.utils import distro_info, update_packages
from fabric.api import env, execute, put, run
if sys.version_info[0] is 2:
    from StringIO import StringIO  # (import-error) pylint:disable=F0401
else:  # pylint:disable=F0401,E0611
    from io import StringIO

# =============================================================================
# Satellite and Capsule Upgrade
# =============================================================================


def satellite6_upgrade():
    """Upgrades satellite from old version to latest version.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        Optional, defaults to available satellite version in CDN.
        URL for the compose repository.
    TO_VERSION
        Satellite version to upgrade to and enable repos while upgrading.
        e.g '6.1','6.2'
    """
    to_version = os.environ.get('TO_VERSION')
    rhev_sat_host = os.environ.get('RHEV_SAT_HOST')
    base_url = os.environ.get('BASE_URL')
    if to_version not in ['6.1', '6.2']:
        print('Wrong Satellite Version Provided to upgrade to. '
              'Provide one of 6.1, 6.2')
        sys.exit(1)
    # Sync capsule and tools repo
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    # Setting yum stdout log level to be less verbose
    set_yum_debug_level()
    # Setup firewall rules on Satellite
    setup_satellite_firewall()
    # Removing rhel-released and rhel-optional repo
    run('rm -rf /etc/yum.repos.d/rhel-{optional,released}.repo')
    print('Wait till Packages update ... ')
    update_packages(quiet=True)
    # Rebooting the system to see possible errors
    if rhev_sat_host:
        reboot(120)
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
    # Stop katello services, except mongod
    run('katello-service stop')
    if to_version == '6.1':
        run('service-wait mongod start')
    run('yum clean all', warn_only=True)
    # Updating the packages again after setting sat6 repo
    print('Wait till packages update ... ')
    print('YUM UPDATE started at: {0}'.format(time.ctime()))
    update_packages(quiet=False)
    print('YUM UPDATE finished at: {0}'.format(time.ctime()))
    # Rebooting the system again for possible errors
    # Only for RHEV based satellite and not for personal one
    if rhev_sat_host:
        reboot(120)
        if to_version == '6.1':
            # Stop the service again which started in restart
            # This step is not required with 6.2 upgrade as installer itself
            # stop all the services before upgrade
            run('katello-service stop')
            run('service-wait mongod start')
    # Verifying impact of BZ #1357655 on upgrade
    if rhev_sat_host:
        run('katello-installer --help', quiet=True)
    # Running Upgrade
    print('SATELLITE UPGRADE started at: {0}'.format(time.ctime()))
    if to_version == '6.1':
        run('katello-installer --upgrade')
    else:
        run('satellite-installer --scenario satellite --upgrade')
    print('SATELLITE UPGRADE finished at: {0}'.format(time.ctime()))
    # Test the Upgrade is successful
    run('hammer -u admin -p {0} ping'.format(admin_password), warn_only=True)
    # Test The status of all katello services
    run('katello-service status', warn_only=True)


def satellite6_capsule_upgrade():
    """Upgrades capsule from existing version to latest version.

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
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
    sat_host = env.get('satellite_host')
    cap_host = env.get('capsule_host')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    # Setup firewall rules on capsule node
    setup_capsule_firewall()
    # Setting Capsule61 Repos
    major_ver = distro_info()[1]
    # Re-register Capsule for 6.2
    # AS per host unification feature: if there is a host registered where the
    # Host and Content Host are in different organizations (e.g. host not in
    # org, and content host in one), the content host will be unregistered as
    # part of the upgrade process.
    if to_version == '6.2':
        ak_name = os.environ.get('CAPSULE_SUBSCRIPTION').split(',')[2].strip(
            ) if os.environ.get('CAPSULE_SUBSCRIPTION') else os.environ.get(
            'RHEV_CAPSULE_AK')
        run('subscription-manager register --org="Default_Organization" '
            '--activationkey={0} --force'.format(ak_name))
    # if CDN Upgrade enable cdn repo
    if os.environ.get('CAPSULE_URL') is None:
        enable_repos('rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
            major_ver, to_version))
    disable_repos('rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
        major_ver, from_version))
    if from_version == '6.1' and major_ver == '6':
        enable_repos('rhel-server-rhscl-{0}-rpms'.format(major_ver))
    if from_version == '6.0':
        # Stop katello services, except mongod
        run('for i in qpidd pulp_workers pulp_celerybeat '
            'pulp_resource_manager httpd; do service $i stop; done')
    run('yum clean all', warn_only=True)
    print('Wait till packages update ... ')
    print('YUM UPDATE started at: {0}'.format(time.ctime()))
    update_packages(quiet=False)
    print('YUM UPDATE finished at: {0}'.format(time.ctime()))
    if from_version == '6.0':
        run('yum install -y capsule-installer', warn_only=True)
        # Copy answer file from katello to capule installer
        run('cp /etc/katello-installer/answers.capsule-installer.yaml.rpmsave '
            '/etc/capsule-installer/answers.capsule-installer.yaml',
            warn_only=True)
    # Generates Capsule Certs file on satelltie and copies in capsule
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
        if to_version == '6.1':
            # Stopping the services again which started in reboot
            run('for i in qpidd pulp_workers pulp_celerybeat '
                'pulp_resource_manager httpd; do service $i stop; done')
    # Setting Up firewall rules
    setup_capsule_firewall()
    # Upgrading Katello installer
    print('CAPSULE UPGRADE started at: {0}'.format(time.ctime()))
    if to_version == '6.1':
        run('capsule-installer --upgrade --certs-tar '
            '/home/{0}-certs.tar'.format(cap_host))
    else:
        run('satellite-installer --scenario capsule --upgrade '
            '--certs-tar /home/{0}-certs.tar'.format(cap_host))
    print('CAPSULE UPGRADE finished at: {0}'.format(time.ctime()))
    # Test The status of all katello services
    run('katello-service status', warn_only=True)


def product_upgrade(product):
    """Task which upgrades the product.

    Product is satellite or capsule.

    :param product: A string. product name wanted to upgrade.
    :param sat_image: A string. Openstack Satellite image name
        from which instance to create.
    :param cap_image: A string. Openstack Capsule image name
        from which instance to create.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username to register the system.
    RHN_PASSWORD
        Red Hat Network password to register the system.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.
    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        URL for the compose repository.
    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
        Optional, defaults to latest available capsule version in CDN.
    FROM_VERSION
        The satellite/capsule current version to upgrade to latest.
        e.g '6.1','6.0'
    TO_VERSION
        To which Satellite/Capsule version to upgrade.
        e.g '6.1','6.2'
    OS
        The OS Version on which the satellite is installed.
        e.g 'rhel7','rhel6'
    SATELLITE_HOSTNAME
        The Satellite hostname to run upgrade on.
        Optional, If want to run upgrade on specific satellite.
    CAPSULE_HOSTNAME
        The Satellite hostname to run upgrade on.
        Optional, If want to run upgrade on specific capsule.
    CAPSULE_SUBSCRIPTION
        List of cv_name, environment, ak_name attached to subscription of
        capsule in defined sequence.
    """
    products = ['satellite', 'capsule']
    if product not in products:
        print('Product name should be one of {0}'.format(', '.join(products)))
        sys.exit(1)
    from_version = os.environ.get('FROM_VERSION')
    if from_version not in ['6.1', '6.0']:
        print('Wrong Upgrade Version Provided. Provide one of 6.1, 6.0.')
        sys.exit(1)
    to_version = os.environ.get('TO_VERSION')
    if to_version not in ['6.1', '6.2']:
        print('Wrong Upgrade Version Provided to upgrade to. Provide one of '
              '6.1, 6.2')
        sys.exit(1)
    # ----------------- Satellite Upgrade ------------------
    # If Personal Satellite Hostname provided
    if os.environ.get('SATELLITE_HOSTNAME'):
        sat_host = os.environ.get('SATELLITE_HOSTNAME')
    # Else run upgrade on rhevm satellite
    else:
        # Get imamge name and Hostname from Jenkins environment
        missing_vars = [
            var for var in ('RHEV_SAT_IMAGE', 'RHEV_SAT_HOST')
            if var not in os.environ]
        # Check if image name and Hostname in jenkins are set
        if missing_vars:
            print('The following environment variable(s) must be set in jenkin'
                  'environment: {0}.'.format(', '.join(missing_vars)))
            sys.exit(1)
        sat_image = os.environ.get('RHEV_SAT_IMAGE')
        sat_host = os.environ.get('RHEV_SAT_HOST')
        # Check If OS is set for creating an instance name in rhevm
        version = os.environ.get('OS')
        if not version:
            print('Please provide OS version as rhel7 or rhel6, And retry !')
            sys.exit(1)
        sat_instance = 'upgrade_satellite_auto_{0}'.format(version)
        # Deleting Satellite instance if already exists
        execute(delete_rhevm_instance, sat_instance)
        print('Turning on Satellite Instance ....')
        execute(create_rhevm_instance, sat_instance, sat_image)
        # Wait Till Instance gets up
        host_pings(sat_host)
        # Subscribe the instance to CDN
        execute(subscribe, host=sat_host)
        # Rebooting the services
        execute(lambda: run('katello-service restart'), host=sat_host)
    # Set satellite hostname in fabric environment
    env['satellite_host'] = sat_host
    # -------------------- Capsule Upgrade ----------------
    if product == 'capsule':
        # If Personal Capsule Hostname provided
        if os.environ.get('CAPSULE_HOSTNAME'):
            cap_host = os.environ.get('CAPSULE_HOSTNAME')
            # For Personal Satellite CAPSULE_SUBSCRIPTION is must
            cap_subscription = os.environ.get('CAPSULE_SUBSCRIPTION')
            if not cap_subscription:
                print('CAPSULE_SUBSCRIPTION environment variable is not '
                      'defined !')
                sys.exit(1)
            elif len(cap_subscription.split(',')) != 3:
                print('CAPSULE_SUBSCRIPTION environment variable is not '
                      'having all the details!')
        # Else run upgrade on rhevm capsule
        else:
            # Get imamge name and Hostname from Jenkins environment
            missing_vars = [
                var for var in (
                    'RHEV_CAP_IMAGE', 'RHEV_CAP_HOST', 'RHEV_CAPSULE_AK')
                if var not in os.environ]
            # Check if image name and Hostname in jenkins are set
            if missing_vars:
                print('The following jenkins environment variable(s) must be '
                      'set: {0}.'.format(', '.join(missing_vars)))
                sys.exit(1)
            cap_image = os.environ.get('RHEV_CAP_IMAGE')
            cap_host = os.environ.get('RHEV_CAP_HOST')
            cap_instance = 'upgrade_capsule_auto_{0}'.format(version)
            # Deleting Capsule instance if already exists
            execute(delete_rhevm_instance, cap_instance)
            print('Turning on Capsule Instance ....')
            execute(create_rhevm_instance, cap_instance, cap_image)
            # Restarting the services on capsule
            execute(lambda: run('katello-service restart'), host=cap_host)
        # Set capsule hostname in fabric environment
        env['capsule_host'] = cap_host
        # Copy ssh key from satellie to capsule
        copy_ssh_key(sat_host, cap_host)
        if os.environ.get('CAPSULE_URL') is not None:
            execute(sync_capsule_tools_repos_to_upgrade, host=sat_host)
    # Run satellite upgrade
    execute(satellite6_upgrade, host=sat_host)
    # Generate foreman debug on satellite
    execute(foreman_debug, 'satellite', host=sat_host)
    if product == 'capsule':
        print('\nRunning Capsule Upgrade ..........')
        # Run capsule upgrade
        execute(satellite6_capsule_upgrade, host=cap_host)
        # Generate foreman debug on capsule
        execute(foreman_debug, 'capsule', host=cap_host)
