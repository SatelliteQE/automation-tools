"""A set of tasks to help upgrade Satellite and Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import novaclient
import os
import sys
import time
from fabric.api import env, execute, run
from novaclient.client import Client
from ovirtsdk.api import API
from ovirtsdk.xml import params
from ovirtsdk.infrastructure import errors
from tools import get_hostname_from_ip, host_pings


class RebootFailedException(Exception):
    """Implements Failure on Rebooting RHEVM instance"""


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


def sync_capsule_tools_repos_to_upgrade(admin_password=None):
    """This syncs capsule repos in Satellite server.

    Useful for upgrading Capsule in feature.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    Following environment variable affects this function:

    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
    FROM_VERSION
        Current Satellite version - to differentiate default organization.
        e.g. '6.1', '6.0'
    CAPSULE_SUBSCRIPTION
        List of cv_name, environment, ak_name attached to subscription of
        capsule in defined sequence.

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
    cv_name, env_name, ak_name = [
        os.environ.get(env_var)
        for env_var in ('CAPSULE_CV', 'CAPSULE_ENVIRONMENT', 'CAPSULE_AK')
    ]
    details = os.environ.get('CAPSULE_SUBSCRIPTION')
    if details is not None:
        cv_name, env_name, ak_name = [
            item.strip() for item in details.split(',')]
    elif not all([cv_name, env_name, ak_name]):
        print('Error! The CV, Env and AK details are not provided for Capsule'
              'upgrade!')
        sys.exit(1)
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    initials = 'hammer -u admin -p {0} '.format(admin_password)
    # First initiate the connection with capsule by syncing it
    capsule_id = str(
        run(initials + 'capsule list | grep {0}'.format(
            env.get('capsule_host')))).split('|')[0].strip()
    if not os.environ.get('CAPSULE_SUBSCRIPTION'):
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
    lc = str(
        run(initials + '--output csv lifecycle-environment list '
            '--organization {0} --name {1}'.format(org, env_name)
            )).split('\n')[1]
    lc_env_id = lc.split(',')[0]
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


def reboot_rhevm_instance(instance_name=None):
    """Reboots the RHEVM instance and waits till get up.

    :param str instance_name: Instance name on rhevm to reboot.
    """
    rhevm_client = get_rhevm_client()
    rhevm_client.vms.get(name=instance_name).reboot()
    time.sleep(5)
    if wait_till_rhev_instance_status(
            instance_name, 'reboot_in_progress', timeout=20):
        print 'The instance {0} is now rebooting. Please Wait ........'.format(
            instance_name)
    else:
        raise RebootFailedException('Failed to reboot rhevm instance '
                                    '{0}'.format(instance_name))
    if wait_till_rhev_instance_status(instance_name, 'up', timeout=400):
        print 'The instance {0} rebooted Successfully'.format(instance_name)
    else:
        raise RebootFailedException('The rhevm instance {0} didn\'t turn up '
                                    'after reboot!'.format(instance_name))
