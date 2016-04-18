import os
import sys
import time
import novaclient
import subprocess

from automation_tools.satellite6.capsule import generate_capsule_certs
from automation_tools.repository import enable_repos, disable_repos
from automation_tools.utils import distro_info, update_packages
from fabric.api import env, execute, put, run
from novaclient.client import Client
from ovirtsdk.api import API
from ovirtsdk.xml import params
from ovirtsdk.infrastructure import errors
import automation_tools
if sys.version_info[0] is 2:
    from StringIO import StringIO  # (import-error) pylint:disable=F0401
else:  # pylint:disable=F0401,E0611
    from io import StringIO

# =============================================================================
# Satellite and Capsule Upgrade
# =============================================================================


def reboot(halt_time=300):
    """Reboots the host.

    Also halts the execution until reboots according to given time.

    :param int halt_time: Halt execution in seconds.
    """
    print('Rebooting the host, please wait .... ')
    try:
        run('reboot', warn_only=True)
    except:
        pass
    time.sleep(halt_time)


def copy_ssh_key(from_host, to_host):
    """This will generate(if not already) ssh-key on from_host
    and copy that ssh-key to to_host.

    Beware that both hosts should have authorized key added
    for test-running host.

    :param from_host: A string. Hostname on which the key to be generated and
        to be copied from.
    :param to_host: A string. Hostname on to which the ssh-key will be copied.

    """
    execute(lambda: run(
        '[ ! -f ~/.ssh/id_rsa.pub ] && '
        'ssh-keygen -f ~/.ssh/id_rsa -t rsa -N \'\'', warn_only=True),
        host=from_host)
    if int(execute(lambda: run('[ -f ~/.ssh/id_rsa.pub ]; '
                               'echo $?'), host=from_host)[from_host]) == 0:
        pub_key = execute(lambda: run(
            'cat ~/.ssh/id_rsa.pub'), host=from_host)[from_host]
        execute(lambda: run('[ ! -f ~/.ssh/authorized_keys ] && '
                            'touch ~/.ssh/authorized_keys',
                            warn_only=True), host=to_host)
        execute(lambda: run(
            'echo "{0}" >> ~/.ssh/authorized_keys'.format(pub_key)),
            host=to_host)


def sync_capsule_tools_repos_to_upgrade(admin_password=None):
    """This syncs capsule repos in Satellite server.

    Useful for upgrading Capsule in feature.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    Following environment variable affects this function:

    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
    FROM_VERSION:
        Current Satellite version - to differentiate default organization.
        e.g. '6.1', '6.0'
    CAP_SUB_DETAILS:
        List of cv_name, environment, ak_name attached to subscription of
        capsule in defined sequence.
        Optional, for upgrade on specific satellite and capsule.

    """
    if os.environ.get('FROM_VERSION') == '6.1':
        org = '\'Default Organization\''
    elif os.environ.get('FROM_VERSION') == '6.0':
        org = 'Default_Organization'
    else:
        print('Wrong FROM_VERSION Provided. Provide one of 6.1 or 6.0...')
        sys.exit(1)
    capsule_repo = os.environ.get('CAPSULE_URL')
    if capsule_repo is None:
        print('The Capsule repo URL is not provided '
              'to perform Capsule Upgrade in feature!')
        sys.exit(1)
    version = distro_info()[1]
    details = os.environ.get('CAP_SUB_DETAILS')
    if details is not None:
        cv_name, env_name, ak_name = [
            item.strip() for item in details.split(',')]
    else:
        cv_name = 'rhel{0}_cv'.format(version)
        env_name = 'DEV'
        ak_name = 'rhel'
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    initials = 'hammer -u admin -p {0} '.format(admin_password)
    # First initiate the connection with capsule by syncing it
    capsule_id = str(
        run(initials + 'capsule list | grep {0}'.format(
            env.get('capsule_host')))).split('|')[0].strip()
    if not os.environ.get('CAP_SUB_DETAILS'):
        run(initials + 'capsule content synchronize --id {0}'.format(
            capsule_id))
    # Create product capsule
    run(initials + 'product create --name capsule6_latest '
        '--organization {0}'.format(org))
    time.sleep(2)
    capsule_sub_id = str(
        run(initials + 'subscription list --organization '
            '{0} | grep capsule6_latest'.format(org))
    ).split('|')[7].strip()
    # create repo
    run(initials + 'repository create --content-type yum '
        '--name capsule6_latest_repo --label capsule6_latest_repo '
        '--product capsule6_latest --publish-via-http true --url {0} '
        '--organization {1}'.format(capsule_repo, org))
    # Sync repos
    run(initials + 'repository synchronize --name capsule6_latest_repo '
        '--product capsule6_latest --organization {0}'.format(org))
    run(initials + 'content-view list --organization {0} | '
        'grep {1}'.format(org, cv_name))
    capsule_repo_id = str(
        run(initials + 'repository list --organization {0} | '
            'grep capsule6_latest_repo'.format(org))).split('|')[0].strip()
    # Add repos to CV
    run(initials + 'content-view add-repository --name {0} '
        '--repository-id {1} --organization {2}'.format(
            cv_name, capsule_repo_id, org))
    # publish cv
    run(initials + 'content-view publish --name {0} '
        '--organization {1}'.format(cv_name, org))
    # promote cv
    lc_env_id = str(
        run(initials + 'lifecycle-environment list '
            '--organization {0} | grep {1}'.format(org, env_name))).split(
                '|')[0].strip()
    cv_ver_id = str(
        run(initials + 'content-view version list --content-view {0} '
            '--organization {1} | grep {0}'.format(
                cv_name, org))).split('|')[0].strip()
    run(initials + 'content-view version promote --content-view {0} '
        '--id {1} --lifecycle-environment-id {2} --organization '
        '{3}'.format(cv_name, cv_ver_id, lc_env_id, org))
    ak_id = str(
        run(initials + 'activation-key list --organization '
            '{0} | grep {1}'.format(org, ak_name))).split('|')[0].strip()
    # Add new product subscriptions to AK
    run(initials + 'activation-key add-subscription --id {0} --quantity 1 '
        '--subscription-id {1}'.format(ak_id, capsule_sub_id))
    # Update subscription on capsule
    execute(
        lambda: run('subscription-manager attach --pool={0}'.format(
            capsule_sub_id)),
        host=env.get('capsule_host'))


def host_pings(host, timeout=15):
    """This ensures the given IP/hostname pings succesfully.

    :param host: A string. The IP or hostname of host.
    :param int timeout: The polling timeout in minutes.

    """
    timeup = time.time() + int(timeout) * 60
    while True:
        command = subprocess.Popen(
            'ping -c1 {0}; echo $?'.format(host),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        output = command.communicate()[0]
        # Checking the return code of ping is 0
        if int(output.split()[-1]) == 0:
            print(
                'SUCCESS !! The given host {0} has been pinged!!'.format(host))
            break
        elif time.time() > timeup:
            print(
                'The timout for pinging the host {0} has reached!'.format(host)
            )
            sys.exit(1)
        else:
            time.sleep(5)


def get_hostname_from_ip(ip, timeout=3):
    """Retrives the hostname by logging into remote machine by IP.
    Specially for the systems who doesnt support reverse DNS.
    e.g usersys machines.

    :param ip: A string. The IP address of the remote host.
    :param int timeout: The polling timeout in minutes.

    """
    timeup = time.time() + int(timeout) * 60
    while True:
        if time.time() > timeup:
            print('The timeout for getting the Hostname from IP has reached!')
            sys.exit(1)
        try:
            output = execute(lambda: run('hostname'), host=ip)
            print('The hostname is: {0}'.format(output[ip]))
            break
        except:
            time.sleep(5)
    return output[ip]


def get_rhevm_client():
    """Creates and returns a client for rhevm.

    The following environment variables affect this command:

    RHEV_USER
        The username of a rhevm project to login.
    RHEV_PASSWD
        The password of a rhevm project to login.
    RHEV_URL
        An url to API of rhevm project.
    """
    username = os.environ.get('RHEV_USER')
    if username is None:
        print('The RHEV_USER environment variable should be defined.')
    password = os.environ.get('RHEV_PASSWD')
    if password is None:
        print('The RHEV_PASSWD environment variable should be defined.')
    api_url = os.environ.get('RHEV_URL')
    if api_url is None:
        print('An RHEV_URL environment variable should be defined.')
    try:
        return API(
            url=api_url,
            username=username,
            password=password,
            insecure=True
        )
    except errors.RequestError:
        print('ERROR ! Invalid Credentials provided for RHEVM.')
        sys.exit(1)


def wait_till_rhev_instance_status(instance_name, status, timeout=5):
    rhevm_client = get_rhevm_client()
    timeup = time.time() + int(timeout) * 60
    while True:
        if time.time() > timeup:
            print('Timeout in turning VM instance {0} ...!'.format(status))
            sys.exit(1)
        vm_status = rhevm_client.vms.get(
            name=instance_name).get_status().get_state()
        print('Current Status: {0}'.format(vm_status))
        if vm_status == status:
            break
            return True
        time.sleep(5)
    rhevm_client.disconnect()


def create_rhevm_instance(instance_name, template_name,
                          datacenter='Default', quota='admin', timeout=5):
    """Creates rhevm Instance from template.

    The assigning template should have network and storage configuration saved
    already.

    ssh_key should be added to openstack project before running automation.
    Else the automation will fail.

    The following environment variables affect this command:

    RHEV_USER
        The username of a rhevm project to login.
    RHEV_PASSWD
        The password of a rhevm project to login.
    RHEV_URL
        An url to API of rhevm project.

    :param instance_name: A string. RHEVM Instance name to create.
    :param template_name: A string. RHEVM image name from which instance
        to be created.
    :param int timeout: The polling timeout in minutes to create rhevm
    instance.
    """
    rhevm_client = get_rhevm_client()
    template = rhevm_client.templates.get(name=template_name)
    datacenter = rhevm_client.datacenters.get(name=datacenter)
    quota = datacenter.quotas.get(name=quota)
    print('Turning on instance {0} from template {1}. Please wait'
          'till it get up ...'.format(instance_name, template_name))
    rhevm_client.vms.add(
        params.VM(
            name=instance_name,
            cluster=rhevm_client.clusters.get('Default'),
            template=template, quota=quota))
    print('Waiting for instance to get up .....')
    if wait_till_rhev_instance_status(instance_name, 'down', timeout=timeout):
        rhevm_client.vms.get(name=instance_name).start()
        if wait_till_rhev_instance_status(
                instance_name, 'up', timeout=timeout):
            print('Instance {0} is now up !'.format(instance_name))
    rhevm_client.disconnect()


def delete_rhevm_instance(instance_name, timeout=5):
    """Deletes RHEVM Instance.

    The following environment variables affect this command:

    USERNAME
        The username of a rhevm project to login.
    PASSWORD
        The password of a rhevm project to login.
    API_URL
        An url to API of rhevm project.

    :param instance_name: A string. RHEVM instance name to delete.
    :param int timeout: The polling timeout in minutes to delete rhevm
    instance.
    """
    rhevm_client = get_rhevm_client()
    vm = rhevm_client.vms.list(query='name={0}'.format(instance_name))
    if not vm:
        print('The instance {0} is not found '
              'in RHEV to delete!'.format(instance_name))
    else:
        print('Deleting instance {0} from RHEVM.....'.format(instance_name))
        if rhevm_client.vms.get(
                name=instance_name).get_status().get_state() == 'up':
            rhevm_client.vms.get(name=instance_name).shutdown()
            if wait_till_rhev_instance_status(instance_name, 'down'):
                rhevm_client.vms.get(name=instance_name).delete()
        elif rhevm_client.vms.get(
                name=instance_name).get_status().get_state() == 'down':
            rhevm_client.vms.get(name=instance_name).delete()
        timeup = time.time() + int(timeout) * 60
        while True:
            if time.time() > timeup:
                print('The timeout for deleting RHEVM instance has reached!')
                sys.exit(1)
            vm = rhevm_client.vms.list(query='name={0}'.format(instance_name))
            if not vm:
                print('Instance {0} is now deleted from RHEVM!'.format(
                    instance_name))
                break
    rhevm_client.disconnect()


def get_openstack_client():
    """Creates client object instance from openstack novaclient API.
    And returns the client object for further use.

    The following environment variables affect this command:

    USERNAME
        The username of an openstack project to login.
    PASSWORD
        The password of an openstack project to login.
    AUTH_URL
        The authentication url of the project.
    PROJECT_ID
        Project ID of an openstack project.

    """
    username = os.environ.get('USERNAME')
    if username is None:
        print('The USERNAME environment variable should be defined.')
    password = os.environ.get('PASSWORD')
    if password is None:
        print('The PASSWORD environment variable should be defined.')
    auth_url = os.environ.get('AUTH_URL')
    if auth_url is None:
        print('The AUTH_URL environment variable should be defined.')
    project_id = os.environ.get('PROJECT_ID')
    if project_id is None:
        print('The PROJECT_ID environment variable should be defined.')
    with Client(
        version=2,
        username=username,
        api_key=password,
        auth_url=auth_url,
        project_id=project_id
    ) as openstack_client:
        openstack_client.authenticate()
        return openstack_client


def create_openstack_instance(
        product, instance_name, image_name, flavor_name, ssh_key, timeout=5):
    """Creates openstack Instance from Image and Assigns a floating IP
    to instance. Also It ensures that instance is ready for testing.

    :param product: A string. A product name of which, instance to create.
    :param instance_name: A string. Openstack Instance name to create.
    :param image_name: A string. Openstack image name from which instance
        to be created.
    :param flavor_name: A string. Openstack flavor_name for instance.
        e.g m1.small.
    :param ssh_key: A string. ssh_key 'name' that required to add
        into this instance.
    :param int timeout: The polling timeout in minutes to assign IP.

    ssh_key should be added to openstack project before running automation.
    Else the automation will fail.

    The following environment variables affect this command:

    USERNAME
        The username of an openstack project to login.
    PASSWORD
        The password of an openstack project to login.
    AUTH_URL
        The authentication url of the project.
    PROJECT_ID
        Project ID of an openstack project.

    """
    network_name = 'satellite-jenkins'
    openstack_client = get_openstack_client()
    # Validate ssh_key is added into openstack project
    openstack_client.keypairs.find(name=ssh_key)
    image = openstack_client.images.find(name=image_name)
    flavor = openstack_client.flavors.find(name=flavor_name)
    network = openstack_client.networks.find(label=network_name)
    floating_ip = openstack_client.floating_ips.create(
        openstack_client.floating_ip_pools.list()[0].name
    )
    # Create instance from the given parameters
    print('Creating new Openstack instance {0}'.format(instance_name))
    instance = openstack_client.servers.create(
        name=instance_name,
        image=image.id,
        flavor=flavor.id,
        key_name=ssh_key,
        network=network.id
    )
    # Assigning floating ip to instance
    timeup = time.time() + int(timeout) * 60
    while True:
        if time.time() > timeup:
            print('The timeout for assigning the floating IP has reached!')
            sys.exit(1)
        try:
            instance.add_floating_ip(floating_ip)
            print('SUCCESS!! The floating IP {0} has been assigned '
                  'to instance!'.format(floating_ip.ip))
            break
        except novaclient.exceptions.BadRequest:
            time.sleep(5)
    # Wait till DNS resolves the IP
    print('Pinging the Host by IP:{0} ..........'.format(floating_ip.ip))
    host_pings(str(floating_ip.ip))
    print('SUCCESS !! The given IP has been pinged!!\n')
    print('Now, Getting the hostname from IP......\n')
    hostname = get_hostname_from_ip(str(floating_ip.ip))
    env['{0}_host'.format(product)] = hostname
    print('Pinging the Hostname:{0} ..........'.format(hostname))
    host_pings(hostname)
    print('SUCCESS !! The obtained hostname from IP is pinged !!')
    # Update the /etc/hosts file
    execute(lambda: run("echo {0} {1} >> /etc/hosts".format(
        floating_ip.ip, hostname)), host=hostname)
    print('The Instance is ready for further Testing .....!!')


def delete_openstack_instance(instance_name):
    """Deletes openstack Instance.

    :param instance_name: A string. Openstack instance name to delete.

    The following environment variables affect this command:

    USERNAME
        The username of an openstack project to login.
    PASSWORD
        The password of an openstack project to login.
    AUTH_URL
        The authentication url of the project.
    PROJECT_ID
        Project ID of an openstack project.

    """
    openstack_client = get_openstack_client()
    try:
        instance = openstack_client.servers.find(name=instance_name)
    except novaclient.exceptions.NotFound:
        print('Instance {0} not found in Openstack project.'.format(
            instance_name
        ))
        return
    instance.delete()
    print('The instance {0} has been deleted from Openstack.'.format(
        instance_name
    ))


def satellite6_upgrade(admin_password=None):
    """Upgrades satellite from already created Openstack image
    of old Satellite version to latest Satellite version compose.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        Optional, defaults to available satellite version in CDN.
        URL for the compose repository.
    FROM_VERSION
        Satellite current version, to disable repos while upgrading.
        e.g '6.1','6.0'
    """
    from_version = os.environ.get('FROM_VERSION')
    if from_version not in ['6.1', '6.0']:
        print('Wrong Satellite Version Provoded. Provide one of 6.1,6.0.')
        sys.exit(1)
    # Sync capsule and tools repo
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    # Setting yum stdout log level to be less verbose
    automation_tools.set_yum_debug_level()
    # Removing rhel-released and rhel-optional repo
    run('rm -rf /etc/yum.repos.d/rhel-{optional,released}.repo')
    print('Wait till Packages update ... ')
    update_packages(quiet=True)
    # Rebooting the system to see possible errors
    execute(reboot, 120, host=env.get('satellite_host'))
    # Setting Satellite61 Repos
    major_ver = distro_info()[1]
    base_url = os.environ.get('BASE_URL')
    # Following disbales the old satellite repo and extra repos enabled
    # during subscribe e.g Load balancer
    disable_repos('*', silent=True)
    enable_repos('rhel-{0}-server-rpms'.format(major_ver))
    if base_url is None:
        enable_repos('rhel-{0}-server-satellite-6.1-rpms'.format(major_ver))
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
    run('service-wait mongod start')
    if major_ver == 7:
        run('service tomcat stop')
    run('yum clean all', warn_only=True)
    # Updating the packages again after setting sat6 repo
    print('Wait till packages update ... ')
    print('YUM UPDATE started at: {0}'.format(time.ctime()))
    update_packages(quiet=False)
    print('YUM UPDATE finished at: {0}'.format(time.ctime()))
    # Rebooting the system again for possible errors
    execute(reboot, 120, host=env.get('satellite_host'))
    # Stop the service again which started in restart
    run('katello-service stop')
    run('service-wait mongod start')
    if major_ver == 7:
        run('service tomcat stop')
    # Running Upgrade
    print('SATELLITE UPGRADE started at: {0}'.format(time.ctime()))
    run('katello-installer --upgrade')
    print('SATELLITE UPGRADE finished at: {0}'.format(time.ctime()))
    # Test the Upgrade is successful
    run('hammer -u admin -p {0} ping'.format(admin_password), warn_only=True)
    # Test The status of all katello services
    run('katello-service status', warn_only=True)


def satellite6_capsule_upgrade(admin_password=None):
    """Upgrades capsule from already created Openstack image
    of old capsule version to latest capsule CDN/compose version.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    CAPSULE_URL
        Optional, defaults to available capsule version in CDN.
        URL for capsule of latest compose to upgrade.
    FROM_VERSION
        Capsule current version, to disable repos while upgrading.
        e.g '6.1','6.0'

    """
    sat_host = env.get('satellite_host')
    cap_host = env.get('capsule_host')
    from_version = os.environ.get('FROM_VERSION')
    if from_version not in ['6.1', '6.0']:
        print('Wrong Capsule Version Provoded. Provide one of 6.1,6.0.')
        sys.exit(1)
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    # Update the packages
    print('Wait till Packages update ... ')
    update_packages(quiet=True)
    # Rebooting the system to see possible errors
    execute(reboot, 120, host=cap_host)
    # Setting Capsule61 Repos
    major_ver = distro_info()[1]
    if os.environ.get('CAPSULE_URL') is None:
        enable_repos('rhel-{0}-server-satellite-capsule-6.1-rpms'.format(
            major_ver))
    disable_repos('rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
        major_ver, from_version))
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
    # Rebooting the system again to see possible errors
    execute(reboot, 120, host=cap_host)
    # Stopping the services again which started in reboot
    run('for i in qpidd pulp_workers pulp_celerybeat '
        'pulp_resource_manager httpd; do service $i stop; done')
    # Upgrading Katello installer
    print('CAPSULE UPGRADE started at: {0}'.format(time.ctime()))
    run('capsule-installer --upgrade --certs-tar '
        '/home/{0}-certs.tar'.format(cap_host))
    print('CAPSULE UPGRADE finished at: {0}'.format(time.ctime()))
    # Test The status of all katello services
    run('katello-service status', warn_only=True)


def product_upgrade(
        product, ssh_key=None, sat_instance=None, sat_image=None,
        sat_flavor=None, cap_instance=None, cap_image=None, cap_flavor=None):
    """Task which upgrades the product.

    Product is satellite or capsule.

    :param product: A string. product name wanted to upgrade.
    :param ssh_key: A string. ssh_key 'name' that is required
        to add into this instance.
    :param sat_instance: A string. Openstack Satellite Instance name
        onto which upgrade will run.
    :param sat_image: A string. Openstack Satellite image name
        from which instance to create.
    :param sat_flavor: A string. Openstack Satelltie flavor_name
        for instance to create. e.g m1.small.
    :param cap_instance: A string. Openstack Capsule Instance name
        onto which upgrade will run.
    :param cap_image: A string. Openstack Capsule image name
        from which instance to create.
    :param cap_flavor: A string. Openstack Capsule flavor_name
        for instance to create. e.g m1.small.

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
    USERNAME
        The username of an openstack project to login.
    PASSWORD
        The password of an openstack project to login.
    AUTH_URL
        The authentication url of the project.
    PROJECT_ID
        Project ID of an openstack project.
    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
        Optional, defaults to latest available capsule version in CDN.
    TOOLS_URL
        The url for sat-tools repo from latest satellite compose.
        Optional, defaults to latest available sat tools version in CDN.
    FROM_VERSION
        The satellite/capsule current version to upgrade to latest.
        e.g '6.1','6.0'
    SATELLITE
        The Satellite hostname to run upgrade on.
        Optional, If want to run upgrade on specific satellite.
    CAPSULE
        The Satellite hostname to run upgrade on.
        Optional, If want to run upgrade on specific capsule.
    CAP_SUB_DETAILS:
        List of cv_name, environment, ak_name attached to subscription of
        capsule in defined sequence.
        Optional, for upgrade on specific satellite and capsule.

    Note: ssh_key should be added to openstack project before
    running automation, else the automation will fail.

    """
    products = ['satellite', 'capsule']
    if product not in products:
        print ('Product name should be one of {0}'.format(', '.join(products)))
        sys.exit(1)
    if not os.environ.get('SATELLITE'):
        # Deleting Satellite instance if any
        execute(delete_openstack_instance, sat_instance)
        print('Turning on Satellite Instance ....')
        execute(
            create_openstack_instance,
            'satellite',
            sat_instance,
            sat_image,
            sat_flavor,
            ssh_key
        )
        # Getting the host name
        sat_host = env.get('satellite_host')
        # Subscribe the instances to CDN
        execute(automation_tools.subscribe, host=sat_host)
    else:
        sat_host = os.environ.get('SATELLITE')
        env['satellite_host'] = sat_host
    # Rebooting the services
    execute(lambda: run('katello-service restart'), host=sat_host)
    # For Capsule Upgrade
    if product == 'capsule':
        if not os.environ.get('CAPSULE'):
            # Deleting Capsule instance if any
            execute(delete_openstack_instance, cap_instance)
            print('Turning on Capsule Instance ....')
            execute(
                create_openstack_instance,
                'capsule',
                cap_instance,
                cap_image,
                cap_flavor,
                ssh_key
            )
            # Getting the host name
            cap_host = env.get('capsule_host')
        else:
            cap_host = os.environ.get('CAPSULE')
            env['capsule_host'] = cap_host
        # Copy ssh key from satellie to capsule
        copy_ssh_key(sat_host, cap_host)
        if os.environ.get('CAPSULE_URL') is not None:
            execute(sync_capsule_tools_repos_to_upgrade, host=sat_host)
    # Run satellite upgrade
    execute(satellite6_upgrade, host=sat_host)
    # Generate foreman debug on satellite
    execute(automation_tools.foreman_debug, 'satellite', host=sat_host)
    if product == 'capsule':
        print('\nRunning Capsule Upgrade ..........')
        # Run capsule upgrade
        execute(satellite6_capsule_upgrade, host=cap_host)
        # Generate foreman debug on capsule
        execute(automation_tools.foreman_debug, 'capsule', host=cap_host)
