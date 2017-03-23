import os
import re
import time

from automation_tools import manage_daemon
from automation_tools.repository import disable_repos
from automation_tools.satellite6.upgrade.tasks import (
    create_rhevm_instance,
    docker_execute_command,
    get_rhevm_client,
    wait_till_rhev_instance_status
)
from automation_tools.satellite6.upgrade.tasks import (
    generate_satellite_docker_clients_on_rhevm,
    refresh_subscriptions_on_docker_clients,
    remove_all_docker_containers,
    sync_tools_repos_to_upgrade
)
from automation_tools.satellite6.upgrade.tools import logger
from fabric.api import env, execute, run

logger = logger()


def katello_agent_version_filter(rpm_name):
    """Helper function to filter the katello-agent version from katello-agent
    rpm name

    :param string rpm_name: The katello-agent rpm name
    """
    return re.search('\d(\-\d|\.\d)*', rpm_name).group()


def personal_clients_upgrade(old_repo, clients):
    """Helper function to run upgrade on user provided clients

    :param string old_repo: The old tools repo to disable before updating
        katello-agent package
    :param list clients: The list of clients onto which katello-agent package
        will be updated
    """
    for client in clients:
        pre = katello_agent_version_filter(execute(
            lambda: run('rpm -q katello-agent'), host=client)[client])
        execute(disable_repos, old_repo, host=client)
        execute(lambda: run('yum update -y katello-agent'), host=client)
        post = katello_agent_version_filter(execute(
            lambda: run('rpm -q katello-agent'), host=client)[client])
        logger.highlight(
            'katello-agent on {0} upgraded from {1} to {2}'.format(
                client, pre, post))


def docker_clients_upgrade(old_repo, clients):
    """Helper function to run upgrade on docker containers as clients

    :param string old_repo: The old tools repo to disable before updating
        katello-agent package
    :param dict clients: The dictonary containing client_name as key and
        container_id as value
    """
    for hostname, container in clients.items():
        logger.info('Upgrading client {0} on docker container: {1}'.format(
            hostname, container))
        pre = katello_agent_version_filter(
            docker_execute_command(container, 'rpm -q katello-agent'))
        docker_execute_command(
            container, 'subscription-manager repos --disable {}'.format(
                old_repo))
        docker_execute_command(container, 'yum update -y katello-agent', True)
        pst = katello_agent_version_filter(
            docker_execute_command(container, 'rpm -q katello-agent'))
        logger.highlight(
            'katello-agent on {0} upgraded from {1} to {2}'.format(
                hostname, pre, pst))


def satellite6_client_setup():
    """Sets up required things on upgrade running machine and on Client to
    perform client upgrade later

    If not personal clients, then it creates docker containers as clients on
    rhevm vm.

    Environment Variable:

    DOCKER_VM
        The Docker VM IP/Hostname on rhevm to create clients
    """
    # If User Defined Clients Hostname provided
    clients6 = os.environ.get('CLIENT6_HOSTS')
    clients7 = os.environ.get('CLIENT7_HOSTS')
    docker_vm = os.environ.get('DOCKER_VM')
    clients_count = os.environ.get('CLIENTS_COUNT')
    from_version = os.environ.get('FROM_VERSION')
    sat_host = env.get('satellite_host')
    if clients6:
        clients6 = [client.strip() for client in str(clients6).split(',')]
        # Sync latest sat tools repo to clients if downstream
        if os.environ.get('TOOLS_URL_RHEL6'):
            logger.info('Syncing Tools repos of rhel6 in Satellite:')
            execute(
                sync_tools_repos_to_upgrade, 'rhel6', clients6, host=sat_host)
    if clients7:
        clients7 = [client.strip() for client in str(clients7).split(',')]
        # Sync latest sat tools repo to clients if downstream
        if os.environ.get('TOOLS_URL_RHEL7'):
            logger.info('Syncing Tools repos of rhel7 in Satellite:')
            execute(
                sync_tools_repos_to_upgrade, 'rhel7', clients7, host=sat_host)
    # Run upgrade on Docker Containers
    if not all([clients6, clients7]):
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
        logger.info('Generating {} clients on RHEL6 and RHEL7 on Docker. '
                    'Please wait .....'.format(clients_count))
        # First delete if any containers running
        execute(
            remove_all_docker_containers, only_running=False, host=docker_vm)
        time.sleep(5)
        # Generate Clients on RHEL 7 and RHEL 6
        clients6 = execute(
            generate_satellite_docker_clients_on_rhevm,
            'rhel6',
            int(clients_count)/2,
            host=docker_vm
        )[docker_vm]
        # Adding sleep to freed up yum lock taken by above client generate task
        time.sleep(30)
        clients7 = execute(
            generate_satellite_docker_clients_on_rhevm,
            'rhel7',
            int(clients_count)/2,
            host=docker_vm
        )[docker_vm]
        # Adding sleep to freed up yum lock taken by above client generate task
        time.sleep(30)
        # Sync latest sat tools repo to clients if downstream
        if all([
            os.environ.get('TOOLS_URL_RHEL6'),
            os.environ.get('TOOLS_URL_RHEL7')
        ]):
            time.sleep(10)
            vers = ['6.0', '6.1']
            logger.info('Syncing Tools repos of rhel7 in Satellite..')
            execute(
                sync_tools_repos_to_upgrade,
                'rhel7',
                # Containers_ids are not requied from sat version > 6.1 to
                # attach the subscriprion to client
                clients7.values() if from_version in vers else clients7.keys(),
                host=sat_host
            )
            time.sleep(10)
            logger.info('Syncing Tools repos of rhel6 in Satellite..')
            execute(
                sync_tools_repos_to_upgrade,
                'rhel6',
                # Containers_ids are not requied from sat version > 6.1 to
                # attach the subscriprion to client
                clients6.values() if from_version in vers else clients6.keys(),
                host=sat_host
            )
        # Refresh subscriptions on clients
        time.sleep(30)
        execute(
            refresh_subscriptions_on_docker_clients,
            clients6.values(),
            host=docker_vm)
        time.sleep(30)
        execute(
            refresh_subscriptions_on_docker_clients,
            clients7.values(),
            host=docker_vm)
    logger.info('Clients are ready for Upgrade.')
    return clients6, clients7


def satellite6_client_upgrade(os_version, clients):
    """Upgrades clients from existing version to latest version

    :param string os_version: The rhel os onto which the client is installed or
        to be installed
    :param list clients: The list of clients onto which the upgrade will be
        performed
    """
    logger.highlight(
        '\n========== {} CLIENTS UPGRADE =================\n'.format(
            os_version.upper()))
    old_version = os.environ.get('FROM_VERSION')
    docker_vm = os.environ.get('DOCKER_VM')
    rhel_ver = os_version[-1]
    old_repo = 'rhel-{0}-server-satellite-tools-{1}-rpms'.format(
        rhel_ver, old_version)
    if os.environ.get('CLIENT6_HOSTS') or os.environ.get('CLIENT7_HOSTS'):
        personal_clients_upgrade(old_repo, clients)
    elif os.environ.get('DOCKER_VM'):
        execute(
            docker_clients_upgrade,
            old_repo,
            clients,
            host=docker_vm
        )
