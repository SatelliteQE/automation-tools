"""A set of tasks to help upgrade Satellite and Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import csv
import novaclient
import os
import re
import sys
import time
import pickle
from automation_tools import (
    setup_alternate_capsule_ports,
    setup_fake_manifest_certificate,
)
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
from automation_tools.bz import bz_bug_is_open
from automation_tools.satellite6.upgrade.tools import (
    get_hostname_from_ip,
    host_pings,
    logger
)
from fabric.api import env, execute, run
from novaclient.client import Client
from ovirtsdk.api import API
from ovirtsdk.xml import params
from ovirtsdk.infrastructure import errors


logger = logger()


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
        logger.warning('The RHEV_USER environment variable should be defined.')
    password = os.environ.get('RHEV_PASSWD')
    if password is None:
        logger.warning(
            'The RHEV_PASSWD environment variable should be defined.')
    api_url = os.environ.get('RHEV_URL')
    if api_url is None:
        logger.warning('An RHEV_URL environment variable should be defined.')
    try:
        return API(
            url=api_url,
            username=username,
            password=password,
            insecure=True
        )
    except errors.RequestError:
        logger.warning('Invalid Credentials provided for RHEVM.')
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
        logger.warning('The USERNAME environment variable should be defined')
    password = os.environ.get('PASSWORD')
    if password is None:
        logger.warning('The PASSWORD environment variable should be defined')
    auth_url = os.environ.get('AUTH_URL')
    if auth_url is None:
        logger.warning('The AUTH_URL environment variable should be defined')
    project_id = os.environ.get('PROJECT_ID')
    if project_id is None:
        logger.warning('The PROJECT_ID environment variable should be defined')
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
    logger.info('Creating new Openstack instance {0}'.format(instance_name))
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
            logger.warning(
                'The timeout for assigning the floating IP has reached!')
            sys.exit(1)
        try:
            instance.add_floating_ip(floating_ip)
            logger.info('SUCCESS!! The floating IP {0} has been assigned '
                        'to instance!'.format(floating_ip.ip))
            break
        except novaclient.exceptions.BadRequest:
            time.sleep(5)
    # Wait till DNS resolves the IP
    logger.info('Pinging the Host by IP:{0} ..........'.format(floating_ip.ip))
    host_pings(str(floating_ip.ip))
    logger.info('SUCCESS !! The given IP has been pinged!!\n')
    logger.info('Now, Getting the hostname from IP......\n')
    hostname = get_hostname_from_ip(str(floating_ip.ip))
    if not hostname:
        sys.exit(1)
    env['{0}_host'.format(product)] = hostname
    logger.info('Pinging the Hostname:{0} ..........'.format(hostname))
    host_pings(hostname)
    logger.info('SUCCESS !! The obtained hostname from IP is pinged !!')
    # Update the /etc/hosts file
    execute(lambda: run("echo {0} {1} >> /etc/hosts".format(
        floating_ip.ip, hostname)), host=hostname)


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
        logger.error('Instance {0} not found in Openstack project.'.format(
            instance_name
        ))
        return
    instance.delete()
    logger.info('Success! The instance {0} has been deleted from '
                'Openstack.'.format(instance_name))


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
            logger.warning(
                'Timeout in turning VM instance {0}.'.format(status))
            sys.exit(1)
        vm_status = rhevm_client.vms.get(
            name=instance_name).get_status().get_state()
        logger.info('Current Status: {0}'.format(vm_status))
        if vm_status == status:
            return True
        time.sleep(5)
    rhevm_client.disconnect()


def create_rhevm_instance(instance_name, template_name, datacenter='Default',
                          quota='admin', cluster='Default', timeout=5):
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
    logger.info('Turning on instance {0} from template {1}. Please wait '
                'till get up ...'.format(instance_name, template_name))
    rhevm_client.vms.add(
        params.VM(
            name=instance_name,
            cluster=rhevm_client.clusters.get(name=cluster),
            template=template, quota=quota))
    if wait_till_rhev_instance_status(
            instance_name, 'down', timeout=timeout):
        rhevm_client.vms.get(name=instance_name).start()
        if wait_till_rhev_instance_status(
                instance_name, 'up', timeout=timeout):
            logger.info('Instance {0} is now up !'.format(instance_name))
            # We can fetch the Instance FQDN only if RHEV-agent is installed.
            # Templates under SAT-QE datacenter includes RHEV-agents.
            if rhevm_client.datacenters.get(name='SAT-QE'):
                # get the hostname of instance
                vm_fqdn = rhevm_client.vms.get(
                    name=instance_name).get_guest_info().get_fqdn()
                logger.info('\t Instance FQDN : %s' % (vm_fqdn))
                # We need value of vm_fqdn so that we can use it with CI
                # For now, we are exporting it as a variable value
                # and source it to use via shell script
                file_path = "/tmp/rhev_instance.txt"
                with open(file_path, 'w') as f1:
                    f1.write('export SAT_INSTANCE_FQDN={0}'.format(vm_fqdn))
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
        logger.info('The instance {0} is not found '
                    'in RHEV to delete!'.format(instance_name))
    else:
        logger.info('Deleting instance {0} from RHEVM.'.format(instance_name))
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
                logger.warning(
                    'The timeout for deleting RHEVM instance has reached!')
                sys.exit(1)
            vm = rhevm_client.vms.list(query='name={0}'.format(instance_name))
            if not vm:
                logger.info('Instance {0} is now deleted from RHEVM!'.format(
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
    logger.info('Syncing latest capsule repos in Satellite ...')
    capsule_repo = os.environ.get('CAPSULE_URL')
    from_version = os.environ.get('FROM_VERSION')
    to_version = os.environ.get('TO_VERSION')
    os_ver = os.environ.get('OS')[-1]
    activation_key = os.environ.get(
        'CAPSULE_AK', os.environ.get('RHEV_CAPSULE_AK'))
    if activation_key is None:
        logger.warning(
            'The AK name is not provided for Capsule upgrade! Aborting...')
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
            logger.info(
                'The product for latest Capsule repo is already created!')
            logger.info('Attaching that product subscription to capsule ....')
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
            cv_name, cv_ver_id, lc_env_id, '1',
            False if from_version == '6.0' else True)
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
        logger.warning(
            'Clients count to generate on Docker should be atleast 1 !')
        sys.exit(1)
    satellite_hostname = os.environ.get('RHEV_SAT_HOST')
    ak = os.environ.get('RHEV_CLIENT_AK_{}'.format(client_os.upper()))
    result = {}
    for count in range(int(clients_count)):
        if bz_bug_is_open('1405085'):
            time.sleep(5)
        hostname = '{0}dockerclient{1}'.format(count, client_os)
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
            # Kill the yum process if its locked with previous task
            kill_process_on_docker_container(container_id, 'yum')
            docker_execute_command(container_id, 'yum clean all')
    else:
        docker_execute_command(container_ids, 'subscription-manager refresh')
        # Kill the yum process if its locked with previous task
        kill_process_on_docker_container(container_id, 'yum')
        docker_execute_command(container_id, 'yum clean all')


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
        logger.warning('The Tools Repo URL for {} is not provided '
                       'to perform Client Upgrade !'.format(client_os))
        sys.exit(1)
    activation_key = os.environ.get(
        'CLIENT_AK_{}'.format(client_os),
        os.environ.get('RHEV_CLIENT_AK_{}'.format(client_os))
    )
    if activation_key is None:
        logger.warning('The AK details are not provided for {0} Client '
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


def docker_execute_command(container_id, command, quiet=False):
    """Executes command on running docker container

    :param string container_id: Running containers id to execute command
    :param string command: Command to run on running container
    :returns command output
    """
    if not isinstance(quiet, bool):
        if quiet.lower() == 'false':
            quiet = False
        elif quiet.lower() == 'true':
            quiet = True
    return run(
        'docker exec {0} {1}'.format(container_id, command), quiet=quiet)


def _extract_sat_cap_version(command):
    """Extracts Satellite and Capsule version

    :param string command: The command to run on Satellite and Capsule that
    returns installed version
    :return string: Satellite/Capsule version
    """
    if command:
        cmd_result = run(command, quiet=True)
        version_re = (
            r'[^\d]*(?P<version>\d(\.\d\.*\d*){1})'
        )
        result = re.search(version_re, cmd_result)
        if result:
            version = result.group('version')
            return version, cmd_result
    return None, cmd_result


def get_sat_cap_version(product):
    """Determines and returns the installed Satellite/Capsule version on system

    :param string product: The product name as satellite/capsule
    :return string: Satellite/Capsule version
    """
    if 'sat' in product.lower():
        _6_2_VERSION_COMMAND = u'rpm -q satellite'
        _LT_6_2_VERSION_COMMAND = (
            u'grep "VERSION" /usr/share/foreman/lib/satellite/version.rb'
        )
    if 'cap' in product.lower():
        _6_2_VERSION_COMMAND = u'rpm -q satellite-capsule'
        _LT_6_2_VERSION_COMMAND = 'None'
    results = (
        _extract_sat_cap_version(cmd) for cmd in
        (_6_2_VERSION_COMMAND, _LT_6_2_VERSION_COMMAND)
    )
    for version, cmd_result in results:
        if version:
            return version
    logger.warning('Unable to detect installed version due to:\n{}'.format(
        cmd_result
    ))


def post_upgrade_test_tasks(sat_host):
    """Run set of tasks for post upgrade tests

    :param string sat_host: Hostname to run the tasks on
    """
    # Execute tasks as post upgrade tests are dependent
    certificate_url = os.environ.get('FAKE_MANIFEST_CERT_URL')
    if certificate_url is not None:
        execute(
            setup_fake_manifest_certificate,
            certificate_url,
            host=sat_host
        )
    execute(setup_alternate_capsule_ports, host=sat_host)
    # Update the Default Organization name, which was updated in 6.2
    execute(hammer, 'organization update --name "Default_Organization" '
            '--new-name "Default Organization" ',
            host=sat_host)


def csv_reader(component, subcommand):
    """
    Reads all component entities data using hammer csv output and returns the
    dict representation of all the entities.

    Representation: {component_name:
    [{comp1_name:comp1, comp1_id:1}, {comp2_name:comp2, comp2_ip:192.168.0.1}]
    }
    e.g:
    {'host':[{name:host1.ab.com, id:10}, {name:host2.xz.com, ip:192.168.0.1}]}

    :param string component: Satellite component name. e.g host, capsule
    :param string subcommand: subcommand for above component. e.g list, info
    :returns dict: The dict repr of hammer csv output of given command
    """
    comp_dict = {}
    entity_list = []
    sat_host = env.get('satellite_host')
    set_hammer_config()
    data = execute(
        hammer, '{0} {1}'.format(component, subcommand), 'csv', host=sat_host
        )[sat_host]
    csv_read = csv.DictReader(str(data.encode('utf-8')).lower().split('\n'))
    for row in csv_read:
        entity_list.append(row)
    comp_dict[component] = entity_list
    return comp_dict


def create_setup_dict(setups_dict):
    """Creates a file to save the return values from setup_products_for_upgrade
     task

    :param string setups_dict: Dictionary of all return value of
    setup_products_for_upgrade
    """
    with open('product_setup', 'wb') as pref:
        pickle.dump(setups_dict, pref)


def get_setup_data():
    """Open's the file to return the values from
    setup_products_for_upgrade to product_upgrade task
    task

    :returns dict: The dict of all the returns values of
    setup_products_for_upgrade that were saved in the product_setup file
    """
    with open('product_setup') as pref:
        data = pickle.load(pref)
    return data


def kill_process_on_docker_container(container_id, process_name):
    """Helper method to kill the process running on docker container

    It first kills the process forcefully and then removes its pid file
    from /var/run directory if exists.

    :param container_id: The container id onto which the process exists
    :param process_name: The process name on a container to be killed
    """
    # Kill the process
    docker_execute_command(
        container_id, 'kill -a -9 {}'.format(process_name), quiet=True)
    # Remove the process pid file
    pid_loc = '/var/run/{}.pid'.format(process_name)
    if docker_execute_command(
        container_id,
        '[ -f {} ]; echo $?'.format(pid_loc)
    ) == '0':
        docker_execute_command(
            container_id,
            'rm -rf {}'.format(pid_loc),
            quiet=True
        )
