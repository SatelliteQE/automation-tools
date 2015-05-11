"""A set of tasks for automating installation of Satellite5 servers.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.

"""
from __future__ import print_function
import os
import sys

from automation_tools import (
    install_prerequisites,
    iso_download,
    setenforce,
    setup_ddns,
    subscribe,
    vm_create,
    vm_destroy,
)
from automation_tools.repository import enable_satellite_repos
from automation_tools.utils import update_packages
from fabric.api import cd, env, execute, run


def satellite5_product_install(create_vm=False, selinux_mode=None):
    """Task which installs only satellite5 product.

    If ``create_vm`` is True then ``vm_destroy`` and ``vm_create`` tasks will
    be run. Make sure to set the required environment variables for those
    tasks. Also, if one of the ``setup_ddns`` required environment variables
    is set then that task will run.

    :param bool create_vm: creates a virtual machine and then install the
        product on it.
    :param str selinux_mode: switches to specified selinux mode.

    """
    # Command-line arguments are passed in as strings.
    if isinstance(create_vm, str):
        create_vm = (create_vm.lower() == 'true')

    if selinux_mode is None:
        selinux_mode = os.environ.get('SELINUX_MODE', 'enforcing')

    if create_vm:
        target_image = os.environ.get('TARGET_IMAGE')
        if target_image is None:
            print('The TARGET_IMAGE environment variable should be defined')
            sys.exit(1)

        execute(vm_destroy, target_image, delete_image=True)
        execute(vm_create)

        if 'DDNS_HASH' in os.environ or 'DDNS_PACKAGE_URL' in os.environ:
            execute(
                setup_ddns, env['vm_domain'], env['vm_ip'], host=env['vm_ip'])

    # When creating a vm the vm_ip will be set, otherwise use the fabric host
    host = env.get('vm_ip', env['host'])

    # Register and subscribe machine to Red Hat
    execute(subscribe, host=host)

    execute(install_prerequisites, host=host)
    execute(setenforce, selinux_mode, host=host)
    execute(enable_satellite_repos, host=host)
    execute(update_packages, warn_only=True)
    execute(satellite5_installer, host=host)


def satellite5_installer():
    """Installs Satellite 5 from an ISO image.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    ISO_URL
        The URL where the ISO will be downloaded.
    SATELLITE_CERT_URL
        The URL where the activation certificate will be downloaded.

    """
    iso_url = os.environ.get('ISO_URL')
    if iso_url is None:
        print('Please provide a valid URL for the ISO image.')
        sys.exit(1)

    # Download and mount the ISO
    print('Downloading ISO...')
    iso_download(iso_url)
    run('umount ISO', warn_only=True)
    run('mkdir -p ISO')
    run('mount -t iso9660 -o loop *.iso ISO')

    # prepare the answer file
    opts = {
        'admin-email': os.environ.get('ADMIN_EMAIL', 'root@localhost'),
        'rhn-username': os.environ.get('RHN_USERNAME', ''),
        'rhn-password': os.environ.get('RHN_PASSWORD', ''),
        'rhn-profile-name': os.environ.get('RHN_PROFILE', ''),
        'rhn-http-proxy': os.environ.get('RHN_HTTP_PROXY', ''),
        'rhn-http-proxy-username':
            os.environ.get('RHN_HTTP_PROXY_USERNAME', ''),
        'rhn-http-proxy-password':
            os.environ.get('RHN_HTTP_PROXY_PASSWORD', ''),
        'ssl-set-org': os.environ.get('SSL_SET_ORG', 'Red Hat'),
        'ssl-set-org-unit': os.environ.get('SSL_SET_ORG_UNIT', 'Satellite QE'),
        'ssl-set-city': os.environ.get('SSL_SET_CITY', 'Brno'),
        'ssl-set-state': os.environ.get('SSL_SET_STATE', 'BRQ'),
        'ssl-set-country': os.environ.get('SSL_SET_COUNTRY', 'CZ'),
        'ssl-password': os.environ.get('SSL_PASSWORD', 'reset'),
        'satellite-cert-url': os.environ.get('SATELLITE_CERT_URL', '')
    }
    run(
        'cat <<EOF > /tmp/answers.txt\n'
        'admin-email={admin-email}\n'
        'rhn-username={rhn-username}\n'
        'rhn-password={rhn-password}\n'
        'rhn-profile-name={rhn-profile-name}\n'
        'rhn-http-proxy={rhn-http-proxy}\n'
        'rhn-http-proxy-username={rhn-http-proxy-username}\n'
        'rhn-http-proxy-password={rhn-http-proxy-password}\n'
        'ssl-config-sslvhost=y\n'
        'ssl-set-org={ssl-set-org}\n'
        'ssl-set-org-unit={ssl-set-org-unit}\n'
        'ssl-set-city={ssl-set-city}\n'
        'ssl-set-state={ssl-set-state}\n'
        'ssl-set-country={ssl-set-country}\n'
        'ssl-set-email={admin-email}\n'
        'ssl-password={ssl-password}\n'
        'satellite-cert-file=/tmp/SATCERT\n'
        'enable-tftp=yes\n'
        'EOF\n'.format(**opts)
    )

    # download a certificate
    print('Downloading Certificate...')
    run('wget -nv -O /tmp/SATCERT {satellite-cert-url}'.format(**opts))
    # ...and run the installer script.
    with cd('ISO'):
        run('./install.pl --answer-file=/tmp/answers.txt --non-interactive '
            '--re-register --run-updater=yes --enable-tftp=yes')
    run('yum -y update')
    run('spacewalk-schema-upgrade -y')
    run('rhn-satellite restart')
