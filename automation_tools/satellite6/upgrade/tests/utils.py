"""All the helper functions, needed for scenarios test case automation to be
added here"""
import os
import pickle
import sys
import time

from automation_tools import manage_daemon
from automation_tools.bz import bz_bug_is_open
from automation_tools.satellite6.hammer import (
    get_attribute_value,
    hammer,
)
from automation_tools.satellite6.upgrade.tasks import (
    create_rhevm_instance,
    get_rhevm_client,
    remove_all_docker_containers,
    wait_till_rhev_instance_status
)
from automation_tools.satellite6.upgrade.tools import logger
from fabric.api import execute, run

rpm1 = 'https://inecas.fedorapeople.org/fakerepos/zoo3/bear-4.1-1.noarch.rpm'
rpm2 = 'https://inecas.fedorapeople.org/fakerepos/zoo3/camel-0.1-1.noarch.rpm'
data = {}
rhev_template = 'sat6-docker-upgrade-template'

logger = logger()


def create_dict(entities_dict):
    """Stores a dictionary of entities created in satellite on the disk

        :param string entities_dict: A dictionary of entities created in
        satellite
        """
    data.update(entities_dict)
    with open('entities_data', 'wb') as pref:
        pickle.dump(data, pref)


def get_entity_data(scenario_name):
    """Fetches the dictionary of entities from the disk depending on the
    Scenario name (class name in which test is defined)

    :param string scenario_name : The name of the class for which the data is
    to fetched

    :returns dict entity_data : Returns a dictionary of entities
    """
    with open('entities_data') as pref:
        entity_data = pickle.load(pref)
        entity_data = entity_data[scenario_name]
    return entity_data


def generate_satellite_docker_clients_on_rhevm_upgrade(
        client_os, clients_count, ak):
    """Generates satellite clients on docker as containers

    :param string client_os: Client OS of which client to be generated
        e.g: rhel6, rhel7
    :param string clients_count: No of clients to generate
    :param string ak : Activation key name, to register clients

    Environment Variables:

    RHEV_SAT_HOST
        The satellite hostname for which clients to be generated and
        registered
    RHEV_CLIENT_AK
        The AK using which client will be registered to satellite
    """
    try:
        clients_count = int(clients_count)
        if clients_count == 0:
            logger.warning(
                'Clients count to generate on Docker should be atleast 1 !')
            sys.exit(1)
        satellite_hostname = get_satellite_host()  # specify satellite hostname
        result = {}
        for count in range(clients_count):
            if bz_bug_is_open('1405085'):
                time.sleep(5)
            hostname = '{0}dockerclient{1}'.format(count, client_os)
            container_id = run(
                'docker run -d -h {0} -e "SATHOST={1}" '
                '-e "AK={2}" upgrade:{3}'.format(
                    hostname, satellite_hostname, ak, client_os))
            result[hostname] = container_id
        return result
    except ValueError:
        print 'Clients count to generate on Docker should be atleast 1 !'


def get_latest_repo_version(cv_name):
    """Calculates the latest CV version to be published

        :param string cv_name : Name of the CV for which version is to be
        calculated

        :return int : Calculated version to be created for CV
        """

    cv_version_data = hammer(
        'content-view version list --content-view {} '
        '--organization-id 1'.format(cv_name))
    latest_cv_ver = sorted([float(data['name'].split(
        '{} '.format(cv_name))[1]) for data in cv_version_data]).pop()
    return get_attribute_value(cv_version_data, '{0} {1}'.format(
        cv_name, latest_cv_ver), 'id')


def dockerize(ak_name):
    """Creates Docker Container's and subscribes them to given AK

        :param string ak_name : Activation Key name, to be used to subscribe
        the docker container's

        :returns dict clients : A dictonary which contain's container name
        and id.

        Environment Variable:

        DOCKER_VM
            The Docker VM IP/Hostname on rhevm to create clients
        """
    docker_vm = os.environ.get('DOCKER_VM')
    # Check if the VM containing docker images is up, else turn on
    rhevm_client = get_rhevm_client()
    instance_name = 'sat6-docker-upgrade'
    template_name = 'sat6-docker-upgrade-template'
    vm = rhevm_client.vms.get(name=instance_name)
    if not vm:
        logger.info('Docker VM for generating Content Host is not created.'
                    'Creating it, please wait..')
        create_rhevm_instance(instance_name, template_name)
        execute(manage_daemon, 'restart', 'docker', host=docker_vm)
    elif vm.get_status().get_state() == 'down':
        logger.info('Docker VM for generating Content Host is not up. '
                    'Turning on, please wait ....')
        rhevm_client.vms.get(name=instance_name).start()
        wait_till_rhev_instance_status(instance_name, 'up', 5)
        execute(manage_daemon, 'restart', 'docker', host=docker_vm)
    rhevm_client.disconnect()
    time.sleep(5)
    logger.info('Generating 1 client on RHEL7 on Docker. '
                'Please wait .....')
    # First delete if any containers running
    execute(
        remove_all_docker_containers, only_running=False, host=docker_vm)
    # Generate Clients on RHEL 7
    time.sleep(30)
    clients = execute(
        generate_satellite_docker_clients_on_rhevm_upgrade,
        'rhel7',
        1,
        ak_name,
        host=docker_vm,
    )[docker_vm]
    return clients


def get_satellite_host():
    """Get the satellite hostname

        :return string : Returns the satellite hostname

        Environment Variable:

        RHEV_SAT_HOST
            This is set, if we are using internal RHEV Templates and VM for
            upgrade.

        SATELLITE_HOSTNAME
            This is set, in case user provides his personal satellite for
            upgrade.
            """
    return os.environ.get(
        'RHEV_SAT_HOST',
        os.environ.get('SATELLITE_HOSTNAME')
    )
