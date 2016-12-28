"""A set of upgrade tasks for upgrading Satellite, Capsule and Client.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import os
import sys

from automation_tools import foreman_debug
from automation_tools.satellite6.log import LogAnalyzer
from automation_tools.satellite6.upgrade.capsule import (
    satellite6_capsule_setup,
    satellite6_capsule_upgrade,
    satellite6_capsule_zstream_upgrade
)
from automation_tools.satellite6.upgrade.client import (
    satellite6_client_setup,
    satellite6_client_upgrade
)
from automation_tools.satellite6.upgrade.satellite import (
    satellite6_setup,
    satellite6_upgrade,
    satellite6_zstream_upgrade
)
from automation_tools.satellite6.upgrade.tasks import (
    get_sat_version
)
from fabric.api import execute


# =============================================================================
# Satellite, Capsule and Client Upgrade
# =============================================================================


def check_necessary_env_variables_for_upgrade(product):
    """Checks if necessary Environment Variables are provided

    :param string product: The product name to upgrade
    """
    failure = []
    # The upgrade product
    products = ['satellite', 'capsule', 'client']
    if product not in products:
        failure.append('Product name should be one of {0}.'.format(
            ', '.join(products)))
    # From which version to upgrade
    if os.environ.get('FROM_VERSION') not in ['6.2', '6.1', '6.0']:
        failure.append('Wrong FROM_VERSION provided to upgrade from. '
                       'Provide one of 6.2, 6.1, 6.0.')
    # To which version to upgrade
    if os.environ.get('TO_VERSION') not in ['6.1', '6.2', '6.3']:
        failure.append('Wrong TO_VERSION provided to upgrade to. '
                       'Provide one of 6.1, 6.2, 6.3')
    # Check If OS is set for creating an instance name in rhevm
    if not os.environ.get('OS'):
        failure.append('Please provide OS version as rhel7 or rhel6, '
                       'And retry !')
    if failure:
        print('Warning !! Cannot Proceed Upgrade as:')
        print('\n'.join(failure))
        sys.exit(1)
    return True


def setup_products_for_upgrade(product, os_version):
    """Sets up product(s) to perform upgrade on

    :param string product: The product name to setup before upgrade
    :param string os_version: The os version on which product is installed
        e.g: rhel6, rhel7
    """
    sat_host = cap_hosts = clients6 = clients7 = None
    sat_host = satellite6_setup(os_version)
    if product == 'capsule':
        cap_hosts = satellite6_capsule_setup(sat_host, os_version)
    if product == 'client':
        clients6, clients7 = satellite6_client_setup()
    return sat_host, cap_hosts, clients6, clients7


def product_upgrade(product):
    """Task which upgrades the product.

    Product is satellite or capsule or client.
    If product is satellite then upgrade only satellite
    If product is capsule then upgrade satellite and capsule
    If product is client then upgrade satellite and client

    :param string product: product name wanted to upgrade.

    Environment Variables necessary to proceed Upgrade:
    -----------------------------------------------------

    FROM_VERSION
        The satellite/capsule current version to upgrade to latest.
        e.g '6.1','6.0'
    TO_VERSION
        To which Satellite/Capsule version to upgrade.
        e.g '6.1','6.2'
    OS
        The OS Version on which the satellite is installed.
        e.g 'rhel7','rhel6'

    Environment variables populated from jenkins:
    ------------------------------------------------------

    RHN_USERNAME
        Red Hat Network username to register the system.
    RHN_PASSWORD
        Red Hat Network password to register the system.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN
    BASE_URL
        URL for the compose repository.
    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
        If CDN, defaults to latest available capsule version
    TOOLS_URL_RHEL6
        The url for rhel6 tools repo from latest satellite compose
        If CDN, defaults to latest available tools version
    TOOLS_URL_RHEL7
        The url for rhel7 tools repo from latest satellite compose
        If CDN, defaults to latest available tools version

    Environment variables required to run upgrade on user's own setup:
    --------------------------------------------------------------------

    SATELLITE_HOSTNAME
        The Satellite hostname to run upgrade on
    CAPSULE_HOSTNAME
        The Satellite hostname to run upgrade on
    CLIENT6_HOSTS
        The RHEL6 clients hostnames to run upgrade on
    CLIENT7_HOSTS
        The RHEL7 clients hostnames to run upgrade on.
    CAPSULE_AK
        Activation Key name attached to the subscription of capsule
    CLIENT_AK
        Activation Key name attached to the subscription of client

    Environment variables required to run upgrade on RHEVM Setup and will be
    fetched from Jenkins:
    ----------------------------------------------------------------------

    RHEV_SAT_IMAGE
        The satellite Image from which satellite instance will be created
    RHEV_SAT_HOST
        The rhevm satellite hostname to run upgrade on
    RHEV_CAP_IMAGE
        The capsule Image from which capsule instance will be created
    RHEV_CAP_HOST
        The rhevm capsule hostname to run upgrade on
    DOCKER_VM
        The Docker VM IP/Hostname on rhevm to create and upgrade clients
    CLIENTS_COUNT
        The number of clients(docker containers) to generate to run upgrade
    RHEV_CAPSULE_AK
        The AK name used in capsule subscription
    RHEV_CLIENT_AK
        The AK name used in client subscription
    """
    if check_necessary_env_variables_for_upgrade(product):
        from_version = os.environ.get('FROM_VERSION')
        to_version = os.environ.get('TO_VERSION')
        sat_host, cap_hosts, clients6, clients7 = setup_products_for_upgrade(
            product, os.environ.get('OS'))
        with LogAnalyzer(sat_host):
            if from_version != to_version:
                current_version = execute(
                    get_sat_version, host=sat_host)
                if not current_version == to_version:
                    execute(satellite6_upgrade, host=sat_host)
            elif from_version == to_version:
                execute(satellite6_zstream_upgrade, host=sat_host)
            # Generate foreman debug on satellite after upgrade
            execute(foreman_debug, 'satellite_{}'.format(sat_host),
                    host=sat_host)
            if product == 'capsule':
                for cap_host in cap_hosts:
                    with LogAnalyzer(cap_host):
                        if from_version != to_version:
                            execute(satellite6_capsule_upgrade, cap_host,
                                    host=cap_host)
                        elif from_version == to_version:
                            execute(satellite6_capsule_zstream_upgrade,
                                    host=cap_host)
                        # Generate foreman debug on capsule after upgrade
                        execute(
                            foreman_debug,
                            'capsule_{}'.format(cap_host),
                            host=cap_host)
            if product == 'client':
                satellite6_client_upgrade('rhel6', clients6)
                satellite6_client_upgrade('rhel7', clients7)
