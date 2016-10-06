import os

from automation_tools.repository import disable_repos
from automation_tools.satellite6.upgrade.tasks import docker_execute_command
from fabric.api import execute, run
from tasks import (
    generate_satellite_docker_clients_on_rhevm,
    refresh_subscriptions_on_docker_clients,
    remove_all_docker_containers,
    sync_tools_repos_to_upgrade
)


def personal_clients_upgrade(old_repo, clients):
    """Helper function to run upgrade on user provided clients

    :param string old_repo: The old tools repo to disable before updating
        katello-agent package
    :param list clients: The list of clients onto which katello-agent package
        will be updated
    """
    for client in clients:
        print('Upgrading client on docker container: {}'.format(client))
        print('Previous katello-agent version:')
        execute(lambda: run('rpm -qa | grep katello-agent'), host=client)
        print('Disabling existing client tools repo:')
        execute(disable_repos, old_repo, host=client)
        print('Upgrading Clients:')
        execute(lambda: run('yum update katello-agent'), host=client)
        print('katello-agent package after installation:')
        execute(lambda: run('rpm -qa | grep katello-agent'), host=client)


def docker_clients_upgrade(old_repo, container_ids):
    """Helper function to run upgrade on docker containers as clients

    :param string old_repo: The old tools repo to disable before updating
        katello-agent package
    :param list container_ids: The list of container_ids onto which
        katello-agent package will be updated
    """
    for client in container_ids:
        print('Upgrading client on docker container: {}'.format(client))
        print('Previous katello-agent version:')
        docker_execute_command(client, 'rpm -qa | grep katello-agent')
        print('Disabling existing client tools repo:')
        docker_execute_command(
            client, 'subscription-manager repos --disable {}'.format(old_repo))
        print('Upgrading clients on Docker Containers')
        docker_execute_command(client, 'yum update katello-agent')
        print('katello-agent package after installation:')
        docker_execute_command(client, 'rpm -qa | grep katello-agent')


def satellite6_client_setup():
    """Sets up required things on upgrade running machine and on Client to
    perform client upgrade later

    If not personal clients, then it creates docker containers as clients on
    rhevm vm.
    """
    # If User Defined Clients Hostname provided
    clients6 = os.environ.get('CLIENT6_HOSTS')
    clients7 = os.environ.get('CLIENT7_HOSTS')
    docker_vm = os.environ.get('DOCKER_VM')
    clients_count = os.environ.get('CLIENTS_COUNT')
    if clients6:
        clients6 = [client.strip() for client in str(clients6).split(',')]
        # Sync latest sat tools repo to clients if downstream
        if os.environ.get('TOOLS_URL_RHEL6'):
            sync_tools_repos_to_upgrade('rhel6', clients6)
    if clients7:
        clients7 = [client.strip() for client in str(clients7).split(',')]
        # Sync latest sat tools repo to clients if downstream
        if os.environ.get('TOOLS_URL_RHEL7'):
            sync_tools_repos_to_upgrade('rhel7', clients7)
    # Run upgrade on Docker Containers
    else:
        # First delete if any containers running
        remove_all_docker_containers(only_running=False)
        # Generate Clients on RHEL 7 and RHEL 6
        clients6 = execute(generate_satellite_docker_clients_on_rhevm(
            'rhel6', int(clients_count)/2), host=docker_vm)[docker_vm]
        clients7 = execute(generate_satellite_docker_clients_on_rhevm(
            'rhel7', int(clients_count)/2), host=docker_vm)[docker_vm]
        # Sync latest sat tools repo to clients if downstream
        if all([
            os.environ.get('TOOLS_URL_RHEL6'),
            os.environ.get('TOOLS_URL_RHEL7')
        ]):
            sync_tools_repos_to_upgrade('rhel6', clients6.keys())
            sync_tools_repos_to_upgrade('rhel7', clients7.keys())
        # Refresh subscriptions on clients
        execute(refresh_subscriptions_on_docker_clients(
            clients6.values()), host=docker_vm)
        execute(refresh_subscriptions_on_docker_clients(
            clients7.values()), host=docker_vm)
    return clients6, clients7


def satellite6_client_upgrade(os_version, clients):
    """Upgrades clients from existing version to latest version

    :param string os_version: The rhel os onto which the client is installed or
        to be installed
    :param list clients: The list of clients onto which the upgrade will be
        performed
    """
    old_version = os.environ.get('FROM_VERSION')
    docker_vm = os.environ.get('DOCKER_VM')
    rhel_ver = os_version[-1]
    old_repo = 'rhel-{0}-server-satellite-tools-{1}-rpms'.format(
        rhel_ver, old_version)
    if os.environ.get('CLIENT6_HOSTS') or os.environ.get('CLIENT7_HOSTS'):
        personal_clients_upgrade(old_repo, clients)
    elif os.environ.get('DOCKER_VM'):
        execute(docker_clients_upgrade, old_repo, clients, host=docker_vm)
