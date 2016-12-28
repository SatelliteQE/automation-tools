"""A set of tasks to help upgrade Satellite and Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import novaclient
import os
import re
import sys
import time
from automation_tools.satellite6.hammer import (
    attach_subscription_to_host_from_satellite,
    get_attribute_value,
    get_product_subscription_id,
    hammer,
    hammer_activation_key_add_subscription,
    hammer_activation_key_content_override,
    hammer_content_view_add_repository,
    hammer_content_view_promote_version,
    hammer_content_view_publish,
    hammer_determine_cv_and_env_from_ak,
    hammer_product_create,
    hammer_repository_create,
    hammer_repository_set_enable,
    hammer_repository_synchronize,
    set_hammer_config
)
from fabric.api import env, execute, run
from novaclient.client import Client
from ovirtsdk.api import API
from ovirtsdk.xml import params
from ovirtsdk.infrastructure import errors
from tools import get_hostname_from_ip, host_pings


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
    if not hostname:
        sys.exit(1)
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


def wait_till_rhev_instance_status(instance_name, status, timeout=5):
    """Waits untill given VM status reached.

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
    timeup = time.time() + int(timeout) * 60
    while True:
        if time.time() > timeup:
            print('Timeout in turning VM instance {0} ...!'.format(status))
            sys.exit(1)
        vm_status = rhevm_client.vms.get(
            name=instance_name).get_status().get_state()
        print('Current Status: {0}'.format(vm_status))
        if vm_status == status:
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
    print('Turning on instance {0} from template {1}. Please wait '
          'till get up ...'.format(instance_name, template_name))
    rhevm_client.vms.add(
        params.VM(
            name=instance_name,
            cluster=rhevm_client.clusters.get('Default'),
            template=template, quota=quota))
    print('Waiting for instance to get up .....')
    if wait_till_rhev_instance_status(
            instance_name, 'down', timeout=timeout):
        rhevm_client.vms.get(name=instance_name).start()
        if wait_till_rhev_instance_status(
                instance_name, 'up', timeout=timeout):
            print('Instance {0} is now up !'.format(instance_name))
    rhevm_client.disconnect()


def delete_rhevm_instance(instance_name, timeout=5):
    """Deletes RHEVM Instance.

    The following environment variables affect this command:

    RHEV_USER
        The username of a rhevm project to login.
    RHEV_PASSWD
        The password of a rhevm project to login.
    RHEV_URL
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


def attach_subscription_to_host_from_content_host(
        subscription_id, dockered_host=False, container_id=None):
    """Attaches product subscription to content host from host itself

    :param string subscription_id: The product uuid/pool_id of which the
    subscription to be attached to content host
    """
    attach_command = 'subscription-manager attach --pool={0}'.format(
        subscription_id)
    if not dockered_host:
        run(attach_command)
    else:
        docker_execute_command(container_id, attach_command)


def sync_capsule_repos_to_upgrade(capsules):
    """This syncs capsule repo in Satellite server and also attaches
    the capsule repo subscription to each capsule

    :param list capsules: The list of capsule hostnames to which new capsule
    repo subscription will be attached

    Following environment variable affects this function:

    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
        If not provided, capsule repo from Red Hat repositories will be enabled
    FROM_VERSION
        Current Satellite version - to differentiate default organization.
        e.g. '6.1', '6.0'
    TO_VERSION
        Upgradable Satellite version - To enable capsule repo
        e.g '6.1', '6.2'
    OS
        OS version to enable next version capsule repo
        e.g 'rhel7', 'rhel6'

    Personal Upgrade Env Vars:

    CAPSULE_AK
        The AK name used in capsule subscription

    Rhevm upgrade Env Vars:

    RHEV_CAPSULE_AK
        The AK name used in capsule subscription
    """
    capsule_repo = os.environ.get('CAPSULE_URL')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    os_ver = os.environ.get('OS')[-1]
    activation_key = os.environ.get(
        'CAPSULE_AK', os.environ.get('RHEV_CAPSULE_AK'))
    if activation_key is None:
        print('Error! The AK name is not provided for Capsule upgrade! '
              'Aborting...')
        sys.exit(1)
    # Set hammer configuration
    set_hammer_config()
    cv_name, env_name = hammer_determine_cv_and_env_from_ak(
        activation_key, '1')
    # If custom capsule repo is not given then
    # enable capsule repo from Redhat Repositories
    product_name = 'capsule6_latest' if capsule_repo \
        else 'Red Hat Satellite Capsule'
    repo_name = 'capsule6_latest_repo' if capsule_repo \
        else 'Red Hat Satellite Capsule {0} (for RHEL {1} Server) ' \
        '(RPMs)'.format(to_version, os_ver)
    try:
        if capsule_repo:
            # Check if the product of latest capsule repo is already created,
            # if not create one and attach the subscription to existing AK
            get_attribute_value(hammer(
                'product list --organization-id 1'), product_name, 'name')
            # If keyError is not thrown as if the product is created already
            print 'The product for latest Capsule repo is aready created!'
            print 'Attaching that product subscription to capsule ....'
        else:
            # In case of CDN Upgrade, the capsule repo has to be resynced
            # and needs to publich/promote those contents
            raise KeyError
    except KeyError:
        # If latest capsule repo is not created already(Fresh Upgrade),
        # So create new....
        if capsule_repo:
            hammer_product_create(product_name, '1')
            time.sleep(2)
            hammer_repository_create(
                repo_name, '1', product_name, capsule_repo)
        else:
            hammer_repository_set_enable(
                repo_name, product_name, '1', 'x86_64')
            repo_name = repo_name.replace('(', '').replace(')', '') + ' x86_64'
        hammer_repository_synchronize(repo_name, '1', product_name)
        # Add repos to CV
        hammer_content_view_add_repository(
            cv_name, '1', product_name, repo_name)
        hammer_content_view_publish(cv_name, '1')
        # Promote cv
        lc_env_id = get_attribute_value(
            hammer('lifecycle-environment list --organization-id 1 '
                   '--name {}'.format(env_name)), env_name, 'id')
        cv_version_data = hammer(
            'content-view version list --content-view {} '
            '--organization-id 1'.format(cv_name))
        latest_cv_ver = sorted([float(data['name'].split(
            '{} '.format(cv_name))[1]) for data in cv_version_data]).pop()
        cv_ver_id = get_attribute_value(cv_version_data, '{0} {1}'.format(
            cv_name, latest_cv_ver), 'id')
        hammer_content_view_promote_version(
            cv_name, cv_ver_id, lc_env_id, '1')
        if capsule_repo:
            hammer_activation_key_add_subscription(
                activation_key, '1', product_name)
        else:
            label = 'rhel-{0}-server-satellite-capsule-{1}-rpms'.format(
                os_ver, to_version)
            hammer_activation_key_content_override(
                activation_key, label, '1', '1')
    # Add this latest capsule repo to capsules to perform upgrade later
    # If downstream capsule, Update AK with latest capsule repo subscription
    if capsule_repo:
        for capsule in capsules:
            if from_version == '6.1':
                subscription_id = get_product_subscription_id(
                    '1', product_name)
                execute(
                    attach_subscription_to_host_from_content_host,
                    subscription_id,
                    host=capsule)
            else:
                attach_subscription_to_host_from_satellite(
                    '1', product_name, capsule)
    else:
        # In upgrade to CDN capsule, the subscription will be already attached
        pass


def generate_satellite_docker_clients_on_rhevm(client_os, clients_count):
    """Generates satellite clients on docker as containers

    :param string client_os: Client OS of which client to be generated
        e.g: rhel6, rhel7
    :param string clients_count: No of clients to generate

    Environment Variables:

    RHEV_SAT_HOST
        The satellite hostname for which clients to be generated and
        registered
    RHEV_CLIENT_AK
        The AK using which client will be registered to satellite
    """
    if int(clients_count) == 0:
        print('Clients count to generate on Docker cannot be Zero !!')
        sys.exit(1)
    satellite_hostname = os.environ.get('RHEV_SAT_HOST')
    ak = os.environ.get('RHEV_CLIENT_AK_{}'.format(client_os.upper()))
    result = {}
    for count in range(int(clients_count)):
        hostname = '{0}DockerClient{1}'.format(count, client_os)
        container_id = run(
            'docker run -d -h {0} -v /dev/log:/dev/log -e "SATHOST={1}" '
            '-e "AK={2}" upgrade:{3}'.format(
                hostname, satellite_hostname, ak, client_os))
        result[hostname] = container_id
    return result


def refresh_subscriptions_on_docker_clients(container_ids):
    """Refreshes subscription on docker containers which are satellite clients

    :param list container_ids: The list of container ids onto which
    subscriptions will be refreshed
    """
    if isinstance(container_ids, list):
        for container_id in container_ids:
            docker_execute_command(
                container_id, 'subscription-manager refresh')
            docker_execute_command(container_id, 'yum clean all')
    else:
        docker_execute_command(container_ids, 'subscription-manager refresh')
        docker_execute_command(container_ids, 'yum clean all')


def sync_tools_repos_to_upgrade(client_os, hosts):
    """This syncs tools repo in Satellite server and also attaches
    the new tools repo subscription onto each client

    :param string client_os: The client OS of which tools repo to be synced
        e.g: rhel6, rhel7
    :param list hosts: The list of capsule hostnames to which new capsule
        repo subscription will be attached

    Following environment variable affects this function:

    TOOLS_URL_{client_os}
        The url of tools repo from latest satellite compose.
    FROM_VERSION
        Current Satellite version - to differentiate default organization.
        e.g. '6.1', '6.0'

    Personal Upgrade Env Vars:

    CLIENT_AK
        The ak_name attached to subscription of client

    Rhevm upgrade Env Vars:

    RHEV_CLIENT_AK
        The AK name used in client subscription
    """
    client_os = client_os.upper()
    tools_repo_url = os.environ.get('TOOLS_URL_{}'.format(client_os))
    if tools_repo_url is None:
        print('The Tools Repo URL for {} is not provided '
              'to perform Client Upgrade !'.format(client_os))
        sys.exit(1)
    activation_key = os.environ.get(
        'CLIENT_AK_{}'.format(client_os),
        os.environ.get('RHEV_CLIENT_AK_{}'.format(client_os))
    )
    if activation_key is None:
        print('Error! The AK details are not provided for {0} Client '
              'upgrade!'.format(client_os))
        sys.exit(1)
    # Set hammer configuration
    set_hammer_config()
    cv_name, env_name = hammer_determine_cv_and_env_from_ak(
        activation_key, '1')
    tools_product = 'tools6_latest_{}'.format(client_os)
    tools_repo = 'tools6_latest_repo_{}'.format(client_os)
    # adding sleeps in between to avoid race conditions
    time.sleep(20)
    hammer_product_create(tools_product, '1')
    time.sleep(10)
    hammer_repository_create(tools_repo, '1', tools_product, tools_repo_url)
    time.sleep(10)
    hammer_repository_synchronize(tools_repo, '1', tools_product)
    hammer_content_view_add_repository(cv_name, '1', tools_product, tools_repo)
    hammer_content_view_publish(cv_name, '1')
    # Promote cv
    lc_env_id = get_attribute_value(
        hammer('lifecycle-environment list --organization-id 1 '
               '--name {}'.format(env_name)), env_name, 'id')
    cv_version_data = hammer(
        'content-view version list --content-view {} '
        '--organization-id 1'.format(cv_name))
    latest_cv_ver = sorted([float(data['name'].split(
        '{} '.format(cv_name))[1]) for data in cv_version_data]).pop()
    cv_ver_id = get_attribute_value(cv_version_data, '{0} {1}'.format(
        cv_name, latest_cv_ver), 'id')
    hammer_content_view_promote_version(cv_name, cv_ver_id, lc_env_id, '1')
    # Add new product subscriptions to AK
    hammer_activation_key_add_subscription(activation_key, '1', tools_product)
    # Add this latest tools repo to hosts to upgrade
    for host in hosts:
        if os.environ.get('FROM_VERSION') in ['6.0', '6.1']:
            subscription_id = get_product_subscription_id('1', tools_product)
            # If not User Hosts then, attach sub to dockered clients
            if not all([
                os.environ.get('CLIENT6_HOSTS'),
                os.environ.get('CLIENT7_HOSTS')
            ]):
                docker_vm = os.environ.get('DOCKER_VM')
                execute(
                    attach_subscription_to_host_from_content_host,
                    subscription_id,
                    True,
                    host,
                    host=docker_vm)
            # Else, Attach subs to user hosts
            else:
                execute(
                    attach_subscription_to_host_from_content_host,
                    subscription_id,
                    host=host)
        else:
            attach_subscription_to_host_from_satellite(
                '1', tools_product, host)


def remove_all_docker_containers(only_running=True):
    """Deletes docker containers from system forcefully

    If only_running is set to true then only running containers will be deleted
    else all running + stopped containers will be deleted

    :param bool only_running: Whether to delete only running containers
    """
    if int(run('docker ps -q{} | wc -l'.format(
            '' if only_running else 'a'))) > 0:
        run('docker rm $(docker ps -q{}) -f'.format(
            '' if only_running else 'a'))
    else:
        print('{} docker containers are not present to delete.'.format(
            'Running' if only_running else ''))


def docker_execute_command(container_id, command, quiet=False):
    """Executes command on running docker container

    :param string container_id: Running containers id to execute command
    :param string command: Command to run on running container
    """
    if not isinstance(quiet, bool):
        if quiet.lower() == 'false':
            quiet = False
        elif quiet.lower() == 'true':
            quiet = True
    run('docker exec {0} {1}'.format(container_id, command), quiet=quiet)


def _extract_sat_version(command):
    """Extracts Satellite version

    :param string command: The command to run on Satellite that returns version
    :return string: Satellite version
    """
    cmd_result = run(command, quiet=True)
    version_re = (
        r'[^\d]*(?P<version>\d(\.\d){1})'
    )
    result = re.search(version_re, cmd_result)
    if result:
        sat_version = result.group('version')
        return sat_version, cmd_result
    else:
        return 'Unavailable', cmd_result


def get_sat_version():
    """Determines and returns the installed Satellite version on system

    :return string: Satellite version
    """
    _SAT_6_2_VERSION_COMMAND = u'rpm -q satellite'
    _SAT_LT_6_2_VERSION_COMMAND = (
        u'grep "VERSION" /usr/share/foreman/lib/satellite/version.rb'
    )
    results = (
        _extract_sat_version(cmd) for cmd in
        (_SAT_6_2_VERSION_COMMAND, _SAT_LT_6_2_VERSION_COMMAND)
    )
    for version, cmd_result in results:
        if version != 'Unavailable':
            return version
    print 'ERROR! The Satellite version is not detected due to:\n{}'.format(
        cmd_result
    )
