"""A set of tasks for automating interactions with Satellite servers.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.

"""
from __future__ import print_function
import os
import random
import socket
import sys
import time
import novaclient
from re import search
from urlparse import urlsplit

from automation_tools.repository import (
    enable_satellite_repos, enable_repos, disable_repos)
from automation_tools.utils import distro_info, update_packages
from fabric.api import cd, env, execute, get, local, put, run
from novaclient.v2 import client

if sys.version_info[0] is 2:
    from urlparse import urljoin  # (import-error) pylint:disable=F0401
    from StringIO import StringIO  # (import-error) pylint:disable=F0401
else:
    from urllib.parse import urljoin  # pylint:disable=F0401,E0611
    from io import StringIO

LIBVIRT_IMAGES_DIR = '/var/lib/libvirt/images'


def unsubscribe():
    """Unregisters a machine from Red Hat"""
    run('subscription-manager unregister', warn_only=True)
    run('subscription-manager clean')


def subscribe(autosubscribe=False):
    """Registers and subscribes machine to Red Hat.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.

    """

    # Registration and subscription is only meaningful for Red Hat Enterprise
    # Linux systems.
    distro, major_version, _ = distro_info()
    if distro.lower() != 'rhel':
        return

    # Register the system.
    for env_var in ('RHN_USERNAME', 'RHN_PASSWORD'):
        if env_var not in os.environ:
            print('The {0} environment variable must be set.'.format(env_var))
            sys.exit(1)
    run(
        'subscription-manager register --force --user={0} --password={1} '
        '--release="{2}Server" {3}'
        .format(
            os.environ['RHN_USERNAME'],
            os.environ['RHN_PASSWORD'],
            major_version,
            '--autosubscribe' if autosubscribe else ''
        )
    )

    # Subscribe the system if a pool ID was provided.
    rhn_poolid = os.environ.get('RHN_POOLID')
    if rhn_poolid is not None:
        has_pool_msg = (
            'This unit has already had the subscription matching pool ID'
        )
        for _ in range(10):
            result = run(
                'subscription-manager subscribe --pool={0}'.format(rhn_poolid),
                warn_only=True
            )
            if result.succeeded or has_pool_msg in result:
                return
            time.sleep(5)
        print('Unable to subscribe system to pool. Aborting.')
        sys.exit(1)


def setup_ddns(entry_domain, host_ip):
    """Task to setup DDNS client

    The following environment variables affect this command:

    * `DDNS_HASH`
    * `DDNS_PACKAGE_URL`

    :param str entry_domain: the FQDN of the host
    :param str entry_hash: host FQDN DDNS entry hash
    :param str host_ip: host IP address

    """
    ddns_hash = os.environ.get('DDNS_HASH')
    if ddns_hash is None:
        print('The DDNS_HASH environment variable should be defined')
        sys.exit(1)

    ddns_package_url = os.environ.get('DDNS_PACKAGE_URL')
    if ddns_package_url is None:
        print('The DDNS_PACKAGE_URL environment variable should be defined')
        sys.exit(1)

    target, domain = entry_domain.split('.', 1)

    run('yum localinstall -y {0}'.format(ddns_package_url))
    run('echo "{0} {1} {2}" >> /etc/redhat-ddns/hosts'.format(
        target, domain, ddns_hash))
    run('echo "127.0.0.1 {0} localhost" > /etc/hosts'.format(entry_domain))
    run('echo "{0} {1}" >> /etc/hosts'.format(
        host_ip, entry_domain))
    run('redhat-ddns-client enable')
    run('redhat-ddns-client')


def setup_proxy(run_katello_installer=True):
    """Task to setup a proxy and block non-proxy traffic from your foreman
    server.

    Proxy information is passed using the PROXY_INFO environmental variable.
    The expected format is::

        PROXY_INFO=proxy://<username>:<password>@<hostname>:<port>

    ``username`` and ``password`` fields can be omitted if the proxy does not
    require authentication, for example::

        PROXY_INFO=proxy://<hostname>:<port>

    """
    if isinstance(run_katello_installer, str):
        run_katello_installer = (run_katello_installer.lower() == 'true')
    proxy_info = os.environ.get('PROXY_INFO')
    if proxy_info is None:
        print('The PROXY_INFO environment variable should be defined')
        sys.exit(1)
    proxy_info = urlsplit(proxy_info)
    if not proxy_info.hostname or not proxy_info.port:
        raise Exception(
            'Proxy configuration should include at least the hostname and port'
        )

    installer_options = {
        'katello-proxy-url': 'http://{0}'.format(proxy_info.hostname),
        'katello-proxy-port': proxy_info.port,
    }
    if proxy_info.username is not None:
        installer_options['katello-proxy-username'] = proxy_info.username
    if proxy_info.password is not None:
        installer_options['katello-proxy-password'] = proxy_info.password
    if run_katello_installer:
        katello_installer(**installer_options)
    else:
        return installer_options


def setup_default_docker():
    """Task to configure system to support Docker as a valid
    Compute Resource for provisioning containers.

    """
    os_version = distro_info()[1]

    # Enable required repository
    if os_version >= 7:
        run(
            'subscription-manager repos --enable "rhel-{0}-server-extras-rpms"'
            .format(os_version)
        )
    else:
        run(
            'yum -y localinstall '
            'http://mirror.pnl.gov/epel/6/x86_64/epel-release-6-8.noarch.rpm'
        )

    # Install ``Docker`` package.
    if os_version >= 7:
        run('yum install -y docker', warn_only=True)
    else:
        run('yum install -y docker-io', warn_only=True)

    # Docker should run as the ``apache`` user
    for group in ('docker', 'dockerroot'):
        if run('id -g {0}'.format(group), quiet=True).succeeded:
            run('usermod -aG {0} apache'.format(group))

    # SElinux workaround let us use ``http://localhost:2375`` for a
    # ``Docker`` Compute Resurce.
    run('sed -i -e "s|^{0}=.*|{0}=\'{1}\'|" /etc/sysconfig/docker'.format(
        'OPTIONS' if os_version >= 7 else 'other_args',
        ' '.join([
            '--selinux-enabled=true',
            '--host tcp://0.0.0.0:2375',
            '--host unix:///var/run/docker.sock',
        ])
    ))

    # Restart ``docker`` service
    # This can silently fail if a pseuo-terminal is used on RHEL 6, due to
    # docker's non-standard approach to daemonizing and its naive init script.
    # See:
    #
    # https://github.com/fabric/fabric/issues/395#issuecomment-1846383
    # https://github.com/fabric/fabric/issues/395#issuecomment-32219270
    # https://github.com/docker/docker/issues/2758
    manage_daemon('restart', 'docker', pty=(os_version >= 7))

    # Check that things look good
    run('docker ps')

    # Pull down a very simple/light Docker container to 'seed' the
    # system with something that can be used right away.
    run('docker pull busybox')


def setup_default_capsule(interface=None, run_katello_installer=True):
    """Task to setup a the default capsule for Satellite

    :param str interface: Network interface name to be used

    """
    if isinstance(run_katello_installer, str):
        run_katello_installer = (run_katello_installer.lower() == 'true')

    forwarders = run(
        'cat /etc/resolv.conf | grep "^nameserver" | awk \'{print $2}\'',
        quiet=True
    ).split('\n')
    forwarders = [forwarder.strip() for forwarder in forwarders]
    if len(forwarders) == 0:
        print('Was not possible to fetch nameserver information')
        sys.exit(1)

    hostname = run('hostname', quiet=True).strip()
    if len(hostname) == 0:
        print('Was not possible to fetch hostname information')
        sys.exit(1)

    domain = hostname.split('.', 1)[1]
    if len(domain) == 0:
        print('Was not possible to fetch domain information')
        sys.exit(1)

    if interface is None:
        run('yum install -y libvirt')
        manage_daemon('enable', 'libvirtd')
        manage_daemon('start', 'libvirtd')
        run('puppet module install -i /tmp domcleal/katellovirt')
        with cd('/tmp/katellovirt/'):
            run('grep -v virbr manifests/libvirt.pp > tempfile')
            run('mv -f tempfile manifests/libvirt.pp')
        run('puppet apply -v -e "include katellovirt" --modulepath /tmp')

        interface = run('ifconfig | grep virbr | awk \'{print $1}\'')
        # Aways select the first interface
        interface = interface.split('\n', 1)[0].strip()
        # Remove any additional visual character like `:` on RHEL7
        interface = search(r'(virbr\d+)', interface).group(1)

        if len(interface) == 0:
            print('Was not possible to fetch interface information')
            sys.exit(1)

    installer_options = {
        'capsule-dns': 'true',
        'capsule-dns-forwarders': forwarders,
        'capsule-dns-interface': interface,
        'capsule-dns-zone': domain,
        'capsule-dhcp': 'true',
        'capsule-dhcp-interface': interface,
        'capsule-tftp': 'true',
        'capsule-tftp-servername': hostname,
        'capsule-puppet': 'true',
        'capsule-puppetca': 'true',
        'capsule-register-in-foreman': 'true',
    }
    if run_katello_installer:
        katello_installer(**installer_options)
    else:
        return installer_options


def setup_email_notification(smtp=None):
    """Configures system to handle email notification.

    NOTE: this task needs a 'katello-service restart', so choose wisely when to
    call it, preferably before another task that restarts the stack, such as
    the 'setup_default_capsule' task.

    :param str smtp: A valid URL to a SMTP server.

    """

    # edit the config file
    if smtp is not None:
        run('sed -i -e "s|address.*|address: {0}|" '
            '/etc/foreman/email.yaml'.format(smtp))
        run('echo "    enable_starttls_auto: false" '
            '>> /etc/foreman/email.yaml')


def setup_fake_manifest_certificate(certificate_url=None):
    """Task to setup a fake manifest certificate

    Allows accepting modified (UUID) redhat-manifest by using a
    fake-manifest-ca.crt

    """
    certificate_url = certificate_url or os.environ.get(
        'FAKE_MANIFEST_CERT_URL')
    if certificate_url is None:
        print('You should specify the fake certificate URL')
        sys.exit(1)

    run('wget -O /etc/candlepin/certs/upstream/fake_manifest.crt '
        '{certificate_url}'.format(certificate_url=certificate_url))

    manage_daemon('restart', 'tomcat6' if distro_info()[1] <= 6 else 'tomcat')


def setup_firewall():
    """Setup firewall rules that Satellite 6 needs to work properly"""
    ports = (
        # Port 443 for HTTPS (secure WWW) must be open for incoming
        # connections.
        443,
        # Port 5671 must be open for SSL communication with managed systems.
        5671,
        # Port 80 for HTTP (WWW) must be open to download the bootstrap files.
        80,
        # Port 8140 must be open for incoming Puppet connections with the
        # managed systems.
        8140,
        # Port 9090 must be open for Foreman Smart Proxy connections with the
        # managed systems.
        9090,
        # Port 22 must be open for connections via ssh
        22,
        # Port 5000 must be open for Docker registry communication.
        5000,
        # Ports 5646 and 5647 for qpidd
        5646,
        5647,
        # Port 8000 for foreman-proxy service
        8000,
        # Port 8443 for Katello access the Islated Capsule
        8443,
    )

    for port in ports:
        rule_exists = run(
            r'iptables -nL INPUT | grep -E "^ACCEPT\s+tcp.*{0}"'.format(port),
            quiet=True,
        ).succeeded
        if not rule_exists:
            run(
                'iptables -I INPUT -m state --state NEW -p tcp --dport {0} '
                '-j ACCEPT'.format(port)
            )

    # To make the changes persistent across reboots when using the command line
    # use this command:
    run('iptables-save > /etc/sysconfig/iptables')


def setup_abrt():
    """Task to setup abrt on foreman

    Currently only available on RHEL7, check BZ #1150197 for more info

    """
    # Check if rubygem-smart_proxy_abrt package is available
    result = run('yum list rubygem-smart_proxy_abrt', quiet=True)
    if result.failed:
        print('WARNING: ABRT was not set up')
        return

    # Install required packages for the installation
    packages = [
        'abrt-cli',
        'rubygem-smart_proxy_abrt',
        'rubygem-smart_proxy_pulp',
        'ruby193-rubygem-foreman_abrt'
    ]
    for package in packages:
        run('yum install -y {0}'.format(package))

    manage_daemon('restart', 'foreman')

    # workaround as sometimes foreman service does not restart with systemctl
    run('touch /usr/share/foreman/tmp/restart.txt')

    # edit the config files
    host = env['host']
    run('echo ":foreman_url: https://{0}" >> /etc/foreman-proxy/settings.yml'
        ''.format(host))
    run('sed -i -e "s/^:enabled: false.*/:enabled: true/" '
        '/etc/foreman-proxy/settings.d/abrt.yml')

    # run the required commands
    manage_daemon('start', 'abrtd')
    manage_daemon('start', 'abrt-ccpp')

    # edit the config files
    run('sed -i -e "s|^URL = .*|URL = https://{0}:8443/abrt/|" '
        '/etc/libreport/plugins/ureport.conf'.format(host))
    run('sed -i -e "s|# SSLVerify = no|SSLVerify = yes|" '
        '/etc/libreport/plugins/ureport.conf')
    run('sed -i -e "s|# SSLClientAuth = .*|SSLClientAuth = puppet|" '
        '/etc/libreport/plugins/ureport.conf')
    run('cp /var/lib/puppet/ssl/certs/ca.pem '
        '/etc/pki/ca-trust/source/anchors/')
    run('update-ca-trust')
    run('abrt-auto-reporting enabled')


def setup_scap_client():
    """Task to setup puppet-foreman_scap_client."""
    run('yum -y install puppet-foreman_scap_client', warn_only=True)


def vm_create():
    """Task to create a VM using snap-guest based on a ``SOURCE_IMAGE`` base
    image.

    Expects the following environment variables:

    VM_RAM
        RAM memory in MB
    VM_CPU
        number of CPU cores
    VM_DOMAIN
        VM's domain name
    SOURCE_IMAGE
        base image name
    TARGET_IMAGE
        target image name
    IMAGE_DIR
        path where the generated image will be stored
    CPU_FEATURE
        copies cpu features of base-metal to vm, thus enabling nested_virt

    The VM will have the TARGET_IMAGE.VM_DOMAIN hostname, but make sure to have
    setup DDNS entry correctly.

    This task will add to the ``env`` the vm_ip and vm_domain

    """
    options = {
        'vm_ram': os.environ.get('VM_RAM'),
        'vm_cpu': os.environ.get('VM_CPU'),
        'vm_domain': os.environ.get('VM_DOMAIN'),
        'source_image': os.environ.get('SOURCE_IMAGE'),
        'target_image': os.environ.get('TARGET_IMAGE'),
        'image_dir': os.environ.get('IMAGE_DIR'),
        'cpu_feature': os.environ.get('CPU_FEATURE'),
    }

    command_args = [
        'snap-guest',
        '-b {source_image}',
        '-t {target_image}',
        '-m {vm_ram}',
        '-c {vm_cpu}',
        '-d {vm_domain}',
        '-n bridge=br0 -f',
    ]

    if options['image_dir'] is not None:
        command_args.append('-p {image_dir}')

    if options['cpu_feature'] is not None:
        command_args.append('--cpu-feature {cpu_feature}')

    command = ' '.join(command_args).format(**options)

    run(command)

    # Give some time to machine boot
    time.sleep(60)

    result = run('ping -c 1 {0}.local'.format(
        options['target_image']))

    env['vm_ip'] = result.split('(')[1].split(')')[0]
    env['vm_domain'] = '{target_image}.{vm_domain}'.format(**options)


def vm_destroy(target_image=None, image_dir=None, delete_image=False):
    """Task to destroy a VM"""
    if target_image is None:
        print('You should specify the virtual machine image')
        sys.exit(1)
    if image_dir is None:
        image_dir = LIBVIRT_IMAGES_DIR
    if isinstance(delete_image, str):
        delete_image = (delete_image.lower() == 'true')

    run('virsh destroy {target_image}'.format(target_image=target_image),
        warn_only=True)
    run('virsh undefine {target_image}'.format(target_image=target_image),
        warn_only=True)

    if delete_image is True:
        image_name = '{target_image}.img'.format(target_image=target_image)
        run('virsh vol-delete --pool default {image_path}'.format(
            image_path=os.path.join(image_dir, image_name)), warn_only=True)


def vm_list(list_all=False):
    """List all virtual machines

    If list_all is False then will show only running virtual machines.

    """
    if isinstance(list_all, str):
        list_all = (list_all.lower() == 'true')

    run('virsh list{0}'.format(' --all' if list_all else ''))


def vm_list_base(base_image_dir=None):
    """List all available base images"""
    if base_image_dir is not None:
        run('snap-guest --list --base-image-dir {0}'.format(base_image_dir))
    else:
        run('snap-guest --list')


def setup_vm_provisioning(interface=None):
    """Task which setup required packages to provision VMs"""
    if interface is None:
        print('A network interface is required')
        sys.exit(1)

    # Check for Nested virtualization support
    result = run(
        'grep -E "^Y" /sys/module/kvm_intel/parameters/nested', quiet=True)
    if result.failed:
        print('Nested Virtualization is not supported on this machine.')
        print('Enabling the Nested Virtualization support.')
        run(
            'echo "options kvm-intel nested=y" > '
            '/etc/modprobe.d/kvm-intel.conf'
        )
        print('Please reboot this machine to enable Nested Virtualization')
        sys.exit(1)

    # Check for virtualization support
    result = run('grep -E "^flags.*(vmx|svm)" /proc/cpuinfo', quiet=True)
    if result.failed:
        print('Virtualization is not supported on this machine')
        sys.exit(1)

    # Install virtualization packages
    run('yum install -y @virtualization')
    manage_daemon('start', 'libvirtd')
    manage_daemon('enable', 'libvirtd')

    # Install other required packages
    packages = (
        'avahi',
        'bash',
        'bridge-utils',
        'cloud-utils',
        'genisoimage',
        'git',
        'kvm',
        'libguestfs-tools',
        'nss-mdns',
        'openssl',
        'perl',
        'perl-Sys-Guestfs',
        'python-virtinst',
        'qemu-img',
        'sed',
        'util-linux',
    )
    run('yum install -y {0}'.format(' '.join(packages)))

    # Setup avahi
    manage_daemon('start', 'avahi-daemon')
    manage_daemon('enable', 'avahi-daemon')

    # Setup snap-guest
    result = run('[ -d /opt/snap-guest ]', warn_only=True)
    if result.failed:
        with cd('/opt'):
            run('git clone git://github.com/lzap/snap-guest.git')
        run('sudo ln -s /opt/snap-guest/snap-guest /usr/local/bin/snap-guest')
    else:
        print('Snap-guest already setup, pulling from upstream')
        with cd('/opt/snap-guest'):
            run('git pull')

    # Setup bridge
    result = run('[ -f /etc/sysconfig/network-scripts/ifcfg-br0 ]', quiet=True)
    if result.failed:
        # Disable NetworkManager
        manage_daemon('disable', 'NetworkManager')
        manage_daemon('stop', 'NetworkManager')
        manage_daemon('enable', 'network')

        # Configure bridge
        ifcfg = '/etc/sysconfig/network-scripts/ifcfg-{0}'.format(interface)
        run('echo NM_CONTROLLED=no >> {0}'.format(ifcfg))
        run('echo BRIDGE=br0 >> {0}'.format(ifcfg))

        ifcfg_br0 = StringIO()
        ifcfg_br0.write('\n')
        ifcfg_br0.write('DEVICE=br0\n')
        ifcfg_br0.write('BOOTPROTO=dhcp\n')
        ifcfg_br0.write('ONBOOT=yes\n')
        ifcfg_br0.write('TYPE=Bridge\n')
        ifcfg_br0.write('NM_CONTROLLED=no\n')
        put(local_path=ifcfg_br0,
            remote_path='/etc/sysconfig/network-scripts/ifcfg-br0')
        ifcfg_br0.close()

        manage_daemon('restart', 'network')

        # Configure iptables to allow all traffic to be forwarded across the
        # bridge
        run('iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT')
        run('iptables-save > /etc/sysconfig/iptables')
        manage_daemon(
            'restart', 'firewalld' if distro_info()[1] >= 7 else 'iptables')
        # Restart the libvirt daemon
        manage_daemon('reload', 'libvirtd')

        # Show configured bridges
        run('brctl show')


def install_prerequisites():
    """Task to ensure that the prerequisites for installation are in place"""

    # Full forward and reverse DNS resolution using a fully qualified domain
    # name. Check that hostname and localhost resolve correctly, using the
    # following commands:
    for command in (
            'ping -c1 localhost', 'ping -c1 $(hostname -s)',
            'ping -c1 $(hostname -f)'):
        if run(command, warn_only=True).failed:
            time.sleep(5)
            run(command)

    # It is recommended that a time synchronizer such as ntpd is installed and
    # enabled on Satellite Server. To enable ntpd and have it persist at
    # bootup:
    run('yum install -y ntp', warn_only=True)
    manage_daemon('enable', 'ntpd', warn_only=True)
    manage_daemon('start', 'ntpd', warn_only=True)


def upstream_install(
        admin_password=None, sam=False, run_katello_installer=True):
    """Task to install Foreman nightly using katello-deploy script"""
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    os_version = distro_info()[1]

    # Install required packages for the installation
    run('yum install -y git ruby')

    run('if [ -d katello-deploy ]; then rm -rf katello-deploy; fi')
    run('git clone https://github.com/Katello/katello-deploy.git')

    run('yum repolist')
    run('cd katello-deploy && ./setup.rb --skip-installer '
        '--os rhel{os_version} {sam}'.format(
            os_version=os_version,
            sam='--sam' if sam else ''
        ))

    installer_options = {
        'foreman-admin-password': admin_password,
    }
    if run_katello_installer:
        katello_installer(sam=sam, **installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def downstream_install(admin_password=None, run_katello_installer=True):
    """Task to install Satellite 6

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        URL for the compose repository.

    """
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    base_url = os.environ.get('BASE_URL')
    if base_url is None:
        print('The BASE_URL environment variable should be defined')
        sys.exit(1)

    satellite_repo = StringIO()
    satellite_repo.write('[satellite]\n')
    satellite_repo.write('name=satellite\n')
    satellite_repo.write('baseurl={0}\n'.format(base_url))
    satellite_repo.write('enabled=1\n')
    satellite_repo.write('gpgcheck=0\n')
    put(local_path=satellite_repo,
        remote_path='/etc/yum.repos.d/satellite.repo')
    satellite_repo.close()

    # Install required packages for the installation
    run('yum install -y katello')

    installer_options = {
        'foreman-admin-password': admin_password,
    }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def cdn_install(run_katello_installer=True):
    """Installs Satellite 6 from CDN.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.
    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.

    """
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    # Install required packages for the installation
    run('yum install -y katello')

    installer_options = {
        'foreman-admin-password': admin_password,
    }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def iso_install(
        admin_password=None, check_sigs=False, run_katello_installer=True):
    """Installs Satellite 6 from an ISO image.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.
    ISO_URL or BASE_URL
        The URL where the ISO will be downloaded.
    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.

    """
    if isinstance(check_sigs, str):
        check_sigs = (check_sigs.lower() == 'true')

    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    iso_url = os.environ.get('ISO_URL') or os.environ.get('BASE_URL')
    if iso_url is None:
        print('Please provide a valid URL for the ISO image.')
        sys.exit(1)

    # Download the ISO
    iso_download(iso_url)

    # Create a 'check-out' folder, mount ISO to it...
    run('mkdir ISO')
    run('mount *.iso ISO -t iso9660 -o loop')
    # ...and run the installer script.
    with cd('/root/ISO'):
        if check_sigs is True:
            run('./install_packages')
        else:
            run('./install_packages --nogpgsigs')

    installer_options = {
        'foreman-admin-password': admin_password,
    }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def sam_upstream_install(admin_password=None):
    """Task to install SAM nightly using katello-deploy script"""
    upstream_install(admin_password, sam=True)


def product_install(distribution, create_vm=False, certificate_url=None,
                    selinux_mode=None):
    """Task which install every product distribution.

    Product distributions are sam-upstream, satellite6-cdn,
    satellite6-downstream, satellite6-iso or satellite6-upstream.

    If ``create_vm`` is True then ``vm_destroy`` and ``vm_create`` tasks will
    be run. Make sure to set the required environment variables for those
    tasks. Also, if one of the ``setup_ddns`` required environment variables
    is set then that task will run.

    If ``certificate_url`` parameter or ``FAKE_MANIFEST_CERT_URL`` env var is
    defined the setup_fake_manifest_certificate task will run.

    :param str distribution: product distribution wanted to install
    :param bool create_vm: creates a virtual machine and then install the
        product on it. Default: False.
    :param str certificate_url: where to fetch a fake certificate.

    """
    # Command-line arguments are passed in as strings.
    if isinstance(create_vm, str):
        create_vm = (create_vm.lower() == 'true')

    install_tasks = {
        'sam-upstream': sam_upstream_install,
        'satellite6-beta': cdn_install,
        'satellite6-cdn': cdn_install,
        'satellite6-downstream': downstream_install,
        'satellite6-iso': iso_install,
        'satellite6-upstream': upstream_install,
    }
    distribution = distribution.lower()
    distributions = install_tasks.keys()
    installer_options = {}

    if distribution not in distributions:
        print('distribution "{0}" should be one of {1}'.format(
            distribution, ', '.join(distributions)))
        sys.exit(1)

    if selinux_mode is None:
        selinux_mode = os.environ.get('SELINUX_MODE', 'enforcing')

    if distribution == 'iso':
        iso_url = os.environ.get('ISO_URL')
        if iso_url is None:
            print('The ISO_URL environment variable should be defined')
            sys.exit(1)

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
    execute(
        enable_satellite_repos,
        cdn=distribution.endswith('cdn'),
        beta=distribution.endswith('beta'),
        host=host
    )
    execute(update_packages, warn_only=True)

    if distribution in ('satellite6-downstream', 'satellite6-iso'):
        execute(java_workaround, host=host)
    # execute returns a dictionary mapping host strings to the given task's
    # return value
    installer_options.update(execute(
        install_tasks[distribution], host=host, run_katello_installer=False
    )[host])

    if distribution in (
            'satellite6-cdn', 'satellite6-downstream', 'satellite6-iso'):
        # execute returns a dictionary mapping host strings to the given task's
        # return value
        installer_options.update(execute(
            setup_default_capsule, host=host, run_katello_installer=False
        )[host])

    # Firewall should be setup after setup_default_capsule clean the puppet
    # module it installs clean already created rules
    execute(setup_firewall, host=host)

    if distribution.startswith('satellite6'):
        execute(setup_default_docker, host=host)
        if os.environ.get('PROXY_INFO'):
            # execute returns a dictionary mapping host strings to the given
            # task's return value
            installer_options.update(execute(
                setup_proxy, host=host, run_katello_installer=False
            )[host])

    execute(
        katello_installer,
        host=host,
        sam=distribution.startswith('sam'),
        **installer_options
    )

    execute(setup_scap_client, host=host)

    certificate_url = certificate_url or os.environ.get(
        'FAKE_MANIFEST_CERT_URL')
    if certificate_url is not None:
        execute(
            setup_fake_manifest_certificate,
            certificate_url,
            host=host
        )


def partition_disk():
    """Re-partitions disk to increase the size of /root to handle
    synchronization of larger repositories.

    """
    run('umount /home')
    run('lvremove -f /dev/mapper/*home')
    run("sed -i '/home/d' /etc/fstab")
    run('lvresize -f -l +100%FREE /dev/mapper/*root')
    run('if uname -r | grep -q el6; then resize2fs -f /dev/mapper/*root; '
        'else xfs_growfs / && mount / -o inode64,remount; fi')


def fix_hostname():
    """Updates `/etc/hosts` with FQDN and IP."""
    ip_addr = run("ping -c 1 $(hostname) | grep 'icmp_seq' "
                  "| awk -F '(' '{print $2}' | awk -F ')' '{print $1}'")
    run('echo "{0} $(hostname)" >> /etc/hosts'.format(ip_addr))


def iso_download(iso_url=None):
    """Downloads the ISO image specified by the ``iso_url`` param.

    The ``iso_url`` could be a full path to the iso file::

        http://example.com/path/to/file.iso

    Or can be a directory path::

        http://example.com/path/to/iso

    When specifying a directory, make sure to have one of MD5SUM, SHA1SUM or
    SHA256SUM available because the iso filename will be fetched by inspecting
    the first found file.

    """
    if iso_url is None:
        print('Please provide a valid URL for the ISO image.')
        sys.exit(1)

    if not iso_url.endswith('.iso'):
        # The following operations will be done remotely because maybe the
        # machine which is running the task could not have access to the ISO
        # server
        iso_filename = None

        # append / in order to urljoin not drop the last URL segment
        if not iso_url.endswith('/'):
            iso_url += '/'

        for sum_file in ('MD5SUM', 'SHA1SUM', 'SHA256SUM'):
            result = run(
                'wget {0} -O - -q'.format(urljoin(iso_url, sum_file)),
                quiet=True,
            )
            if result.succeeded:
                iso_filename = search('\w+\s+\*?([^\s]+)', result).group(1)
                break

        if iso_filename is None:
            print('Unable to fetch the ISO filename')
            sys.exit(1)

        iso_url = urljoin(iso_url, iso_filename)

    run('wget {0}'.format(iso_url), quiet=True)


# Miscelaneous tasks ==========================================================
def create_personal_git_repo(name, private=False):
    """Creates a new personal git repository under the public_git repository"""
    # Command-line arguments are passed in as strings.
    if isinstance(private, str):
        private = (private.lower() == 'true')

    # Create a repository locally, upload it and delete the local repository.
    # Do not create a repository directly on the remote machine because its
    # version of git may be old.
    repo_name = '{0}.git'.format(name)
    local(
        'git init --bare --shared={0} {1}'
        .format('none' if private else 'all', repo_name)
    )
    run('install -d -m 755 ~/public_git/')
    put(repo_name, '~/public_git/')
    local('rm -rf {0}'.format(repo_name))


def performance_tuning(running_on_vm=True):
    """Task which tunes up the Satellite 6 performance

    Set running_on_vm to False if improving performance on a bare metal machine

    """
    # Command-line arguments are passed in as strings.
    if isinstance(running_on_vm, str):
        running_on_vm = (running_on_vm.lower() == 'true')

    # httpd configuration
    run('sed -i -e "s/^KeepAlive.*/KeepAlive On/" '
        '/etc/httpd/conf/httpd.conf')
    manage_daemon('restart', 'httpd')

    # tuned setup
    run('yum install -y tuned', warn_only=True)
    manage_daemon('enable', 'tuned')
    manage_daemon('start', 'tuned')
    if running_on_vm:
        run('tuned-adm profile virtual-guest')
    else:
        run('tuned-adm profile throughput-performance')


def add_repo(repo_name=None, repo_url=None):
    """Adds a new repo to the system based on the repo_url"""
    if repo_url is not None:
        if repo_name is None:
            repo_name = urlsplit(repo_url).netloc
        repo_file = (
            '[{0}]\n'
            'name={0}\n'
            'baseurl={1}\n'
            'enabled=1\n'.format(repo_name, repo_url)
        )
        with cd('/etc/yum.repos.d/'):
            run('echo "{0}" >> automation-tools.repo'.format(repo_file))
    else:
        print('add_repo requires a repo_url to make any changes.')
        sys.exit(1)


# Client registration
# ==================================================
def clean_rhsm():
    """Removes pre-existing Candlepin certs and resets RHSM."""
    print('Erasing existing Candlepin certs, if any.')
    run('yum erase -y $(rpm -qa |grep katello-ca-consumer)', quiet=True)
    print('Resetting rhsm.conf to point to cdn.')
    run("sed -i -e 's/^hostname.*/hostname=subscription.rhn.redhat.com/' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e 's|^prefix.*|prefix=/subscription|' /etc/rhsm/rhsm.conf")
    run("sed -i -e 's|^baseurl.*|baseurl=https://cdn.redhat.com|' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e "
        "'s/^repo_ca_cert.*/repo_ca_cert=%(ca_cert_dir)sredhat-uep.pem/' "
        "/etc/rhsm/rhsm.conf")


def update_basic_packages():
    """Updates some basic packages before we can run some real tests."""
    subscribe(autosubscribe=True)
    update_packages('subscription-manager', 'yum-utils', quiet=True)
    run('yum install -y yum-plugin-security yum-security', quiet=True)
    run('rpm -q subscription-manager python-rhsm')
    # Clean up
    unsubscribe()


def client_registration_test(clean_beaker=True, update_packages=True):
    """Register client against Satellite 6 and runs tests."""

    # Since all arguments are turned to string, if no defaults are
    # used...
    if isinstance(clean_beaker, str):
        clean_beaker = (clean_beaker.lower() == 'true')
    if isinstance(update_packages, str):
        update_packages = (update_packages.lower() == 'true')

    # Org
    org = os.getenv('ORG', 'Default_Organization')
    # Activation Key
    act_key = os.getenv('ACTIVATIONKEY')
    if not act_key:
        print('You need to provide an activationkey.')
        sys.exit(1)
    # Candlepin cert RPM
    cert_url = os.getenv('CERTURL')
    if not cert_url:
        print('You need to install the Candlepin Cert RPM.')
        sys.exit(1)

    # If this is a Beaker box, 'disable' Beaker repos
    if clean_beaker is True:
        run('mv /etc/yum.repos.d/beaker* .', warn_only=True)

    # Update some basic packages before we try to register
    if update_packages is True:
        update_basic_packages()

    # Install the cert file
    run('rpm -Uvh {0}'.format(cert_url), warn_only=True)

    # Register and subscribe
    print('Register/Subscribe using Subscription-manager.')
    run('subscription-manager register --force'
        ' --org="{0}"'
        ' --activationkey="{1}"'
        ''.format(org, act_key))
    print('Refreshing Subscription-manager.')
    run('subscription-manager refresh')
    print('Performing yum clean up.')
    run('yum clean all', quiet=True)
    print('"Firefox" and "Telnet" should not be installed.')
    run('rpm -q firefox telnet', warn_only=True)
    print('Installing "Firefox" and "Telnet".')
    run('yum install -y firefox telnet', quiet=True)
    print('"Firefox" and "Telnet" should be installed.')
    run('rpm -q firefox telnet')
    print('Removing "Firefox" and "Telnet".')
    run('yum remove -y firefox telnet', quiet=True)
    print('Checking if "Firefox" and "Telnet" are installed.')
    run('rpm -q firefox telnet', warn_only=True)
    print('Installing "Web Server" group.')
    run('yum groupinstall -y "Web Server"', quiet=True)
    print('Checking for "httpd" and starting it.')
    run('rpm -q httpd')
    manage_daemon('start', 'httpd', warn_only=True)
    print('Stopping "httpd" service and remove "Web Server" group.')
    manage_daemon('stop', 'httpd', warn_only=True)
    run('yum groupremove -y "Web Server"', quiet=True)
    print('Checking if "httpd" is really removed.')
    run('rpm -q httpd', warn_only=True)
    # Install random errata
    install_errata()

    # Clean up
    unsubscribe()
    clean_rhsm()


def install_errata():
    """Randomly selects an errata and installs it."""

    erratum = run('yum list-sec', quiet=True)

    if erratum:
        erratum = erratum.split('\r\n')
        errata = [entry for entry in erratum if entry.startswith('RH')]
        if errata:
            # Pick a random errata from the available list
            # Example: RHBA-2013:1357 bugfix   man-pages-5.10.2-1.el5.noarch
            rnd_errata = errata[random.randint(0, len(errata) - 1)]
            # ... and parse what we want
            rnd_errata = rnd_errata.split(' ')[0]
            print('Applying errata: {0}'.format(rnd_errata))
            # Apply the errata
            update_packages(
                '--advisory', '"{0}"'.format(rnd_errata), quiet=True)
        else:
            print('NO ERRATA AVAILABLE')
    else:
        print('FAILED TO OBTAIN ERRATA INFORMATION')


def install_katello_agent():
    """Installs the 'katello-agent' package."""
    # Check that the package is not installed
    run('rpm -q katello-agent', warn_only=True)
    # Install it
    run('yum install -y katello-agent')
    # Now, check that the package is installed...
    run('rpm -q katello-agent')
    # ...and that 'goerd' is running.
    manage_daemon('status', 'goferd')


def remove_katello_agent():
    """Removes the 'katello-agent' package."""
    # Check that the package is installed
    run('rpm -q katello-agent')
    # Remove it
    run('rpm -e katello-agent')
    # Now, check that the package is indeed gone...
    run('rpm -q katello-agent', warn_only=True)
    # ...and that 'goerd' is not running.
    manage_daemon('status', 'goferd', warn_only=True)


def errata_upgrade():
    """Upgrades the host with the given errata packages.

    Note:
    1. If you are running this for satellite6, this method assumes that
    satellite6 is already installed in the host.
    2. If you are running this for rhcommon, this method assumes that the
    katello-agent is already installed in the host.

    The following environment variables affect this command

    TEST_PROFILE
        Test Profile for the errata test
        Known test profiles:
        rhcommon:
        `satellite6-rhcommon-5`      - rhel5
        `satellite6-rhcommon-6`      - rhel6
        TBD                          - rhel7

        satellite6:
        TBD                          - rhel5
        `satellite6-rhel-server-6`   - rhel6
        `satellite6-rhel-server-7`   - rhel7

    PACKAGE_1
        Package 1 to be installed

    SOURCE_SERVER_1
        Source Server for PACKAGE_1 install

    PACKAGE_2
        Package 2 to be used

    """
    package1 = os.environ['PACKAGE_1']
    package2 = os.environ['PACKAGE_2']

    # Install packages
    result = run('which yum-config-manager', warn_only=True)
    if result.succeeded:
        run('yum-config-manager --enable "beaker*"')
    else:
        run('mv ~/beaker-* /etc/yum.repos.d/', warn_only=True)
    run('yum localinstall -y http://{0}/mnt/{1}dist/{2}.noarch.rpm'
        .format(os.environ['SOURCE_SERVER_1'], package2, package1))
    run('yum --nogpgcheck -y install nfs-utils')
    run('yum install -y perl-Date-Manip')

    run('echo {0}_TEST_PROFILE={1} >> /etc/sysconfig/{2}.conf'
        .format(package1.upper(), os.environ['TEST_PROFILE'], package1))
    run('echo TREE=$(grep -E -m 1 \'^(url|nfs) \' /root/anaconda-ks.cfg | '
        'sed \'s|^[^/]*/\(.*\)$|/\1| ; s|//|| ; s|"||g\') '
        '>> /etc/sysconfig/{0}.conf'.format(package1))
    run('echo {0}_{1}_STABLE=true >> /etc/sysconfig/{1}.conf'
        .format(package1.upper(), package2.upper()))
    run('cat /etc/sysconfig/{0}.conf'.format(package1))
    run('rm -f /etc/cron.d/{0}rebuild.cron'.format(package1))

    # Start <package1>d service
    manage_daemon('start', '{0}d'.format(package1))

    # Follow the log, run will return when the system is rebooting
    run('tail -f /var/log/{0}d'.format(package1), warn_only=True)

    # Monitor the system reboot
    time.sleep(5)  # Give some time to process reboot request
    timeout = 300  # Wait up to 5 minutes to machine boot
    while timeout >= 0:
        try:
            sock = socket.socket()
            sock.settimeout(57)
            sock.connect((env['host'], 22))
            sock.close()
            return
        except socket.error as err:
            # During the reboot the following errors are expected:
            # * Operation timed out (60)
            # * Connection refused (61)
            if err.errno not in (60, 61):
                raise
            if err.errno == 60:
                timeout -= sock.gettimeout()
        finally:
            sock.close()
        time.sleep(3)
        timeout -= 3
    print('Timed out while waiting machine to reboot.')
    sys.exit(1)


def run_errata():
    """Run the errata to upgrade packages.

    The following environment variables affect this command:

    ERRATA_NUMBER
        Errata number of the errata to test. Format: xxxx:xxxxx Eg: 2014:19309
    PACKAGE_2
        Package 2 to be used

    """
    package2 = os.environ['PACKAGE_2']
    errata_number = os.environ['ERRATA_NUMBER']
    if errata_number is None:
        print('The ERRATA_NUMBER variable should be defined')
        sys.exit(1)

    # See: https://bugzilla.redhat.com/show_bug.cgi?id=1182352
    run('update-{0}d-settings'.format(package2))

    run('{0}-setup-channel-cache'.format(package2))
    run('{0}-cd --create {1} && {0}-upgrade'.format(package2, errata_number))

    # After this you can see the upgraded packages
    # Run `<package2>-downgrade` if you want to revert to the old packages


# =============================================================================
# Utility tasks
# =============================================================================
def foreman_debug(tarball_name=None, local_path=None):
    """Generates and download the foreman-debug generated tarball

    :param str tarball_name: The tarball file name which will be downloaded
        relative to the current working directory. If ``None`` the tarball will
        be named foreman-debug-<timestamp>.
    :param str local_path: The local path given by user to save foreman-debug
        tar file eg., /home/$user/Downloads/.  By default, the tar file will
        be saved in automation-tools root folder.

    """
    if tarball_name is None:
        tarball_name = 'foreman-debug-{0}'.format(int(time.time()))

    with cd('/tmp'):
        run('foreman-debug -q -d {0}'.format(tarball_name), quiet=True)
        get(
            local_path=local_path if local_path else '%(basename)s',
            remote_path='/tmp/{0}/{0}.tar.xz'.format(tarball_name),
        )

    release = run(
        'cat /etc/yum.repos.d/satellite.repo | grep baseurl | cut -d "/" -f 7',
        quiet=True
    )
    print('Satellite release: {0}'.format(release))


# =============================================================================
# Helper functions
# =============================================================================
def java_workaround():
    """By default java-1.8.0-openjdk will be installed on RHEL 6.6 but it makes
    the katello-installer fail. Install java-1.7.0-openjdk which is the
    recommended version for RHEL 6.6.

    """
    if distro_info() == ('rhel', 6, 6):
        run('yum install -y java-1.7.0-openjdk')


def katello_installer(debug=True, sam=False, verbose=True, **kwargs):
    """Runs the installer with ``kwargs`` as command options. If ``sam`` is
    True

    """
    # capsule-dns-forwarders should be repeated if setting more than one value
    # check if a list is being received and repeat the option with different
    # values
    extra_options = []
    if ('capsule-dns-forwarders' in kwargs and
            isinstance(kwargs['capsule-dns-forwarders'], list)):
        forwarders = kwargs.pop('capsule-dns-forwarders')
        for forwarder in forwarders:
            extra_options.append(
                '--capsule-dns-forwarders="{0}"'.format(forwarder))

    run('{0}-installer {1} {2} {3} {4}'.format(
        'sam' if sam else 'katello',
        '-d' if debug else '',
        '-v' if verbose else '',
        ' '.join([
            '--{0}="{1}"'.format(key, val) for key, val in kwargs.items()
        ]),
        ' '.join(extra_options)
    ))


def manage_daemon(action, daemon, pty=True, warn_only=False):
    """Manage a system daemon

    :param str action: Daemon action like start, stop, restart, info
    :param str daemon: Daemon name to perform the action
    :param bool pty: Controls the creation of a pseudo-terminal when managing
        the daemon. Some daemons actions fail with pty=True.
    :param bool warn_only: Will be passed directly to Fabric's run

    """
    if distro_info()[1] >= 7:
        command = 'systemctl {} {}'.format(action, daemon)
    else:
        if action in ('enable', 'disable'):
            command = 'chkconfig {} {}'.format(
                daemon,
                'on' if action == 'enable' else 'off'
            )
        else:
            command = 'service {} {}'.format(daemon, action)
    return run(command, pty=pty, warn_only=warn_only)


def setenforce(mode):
    """Modify the mode SELinux is running in

    :param mode: Use 'enforcing' or 1 or True to put SELinux in enforcing mode.
        Use 'permissive' or 0 or False to put SELinux in permissive mode.

    """
    if isinstance(mode, str):
        mode = mode.lower()

    enforcing_modes = ('enforcing', 1, True)
    permissive_modes = ('permissive', 0, False)
    if mode in enforcing_modes:
        mode = 1
    elif mode in permissive_modes:
        mode = 0
    else:
        raise ValueError('Mode should be one of {0}'.format(
            enforcing_modes + permissive_modes
        ))

    run('setenforce {0}'.format(mode))


def get_hostname_from_ip(ip):
    """Retrives the hostname by logging into remote machine by IP.
    Specially for the systems who doesnt support reverse DNS.
    e.g usersys machines.

    :param ip: A string. The IP address of the remote host.

    """
    return execute(lambda: run('hostname'), host=ip)[ip]


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
    with client.Client(
        username=username,
        api_key=password,
        auth_url=auth_url,
        project_id=project_id
    ) as openstack_client:
        openstack_client.authenticate()
        return openstack_client


def create_openstack_instance(instance_name, image_name, flavor_name, ssh_key):
    """Creates openstack Instance from Image and Assigns a floating IP
    to instance.

    :param instance_name: A string. Openstack Instance name to create.
    :param image_name: A string. Openstack image name from which instance
        to be created.
    :param flavor_name: A string. Openstack flavor_name for instance.
        e.g m1.small.
    :param ssh_key: A string. ssh_key 'name' that required to add
        into this instance.

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
    instance = openstack_client.servers.create(
        name=instance_name,
        image=image.id,
        flavor=flavor.id,
        key_name=ssh_key,
        network=network.id
    )
    # Assigning floating ip to instance
    while True:
        try:
            instance.add_floating_ip(floating_ip)
            break
        except novaclient.exceptions.BadRequest:
            time.sleep(5)
    # Wait till DNS resolves the IP
    time.sleep(600)
    # Getting Hostname from IP
    env['instance_host'] = get_hostname_from_ip(str(floating_ip.ip))


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


def satellite6_upgrade(admin_password=None):
    """Upgrades satellite from already created Openstack image
    of old Satellite version to latest Satellite version compose.

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        URL for the compose repository.

    """
    base_url = os.environ.get('BASE_URL')
    if base_url is None:
        print('The BASE_URL environment variable should be defined')
        sys.exit(1)
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    # Removing rhel-released and rhel-optional repo
    run('rm -rf /etc/yum.repos.d/rhel-{optional,released}.repo')
    # Update the packages
    update_packages(quiet=True)
    # Setting Satellite61 Repos
    major_ver = distro_info()[1]
    enable_repos('rhel-{0}-server-satellite-6.1-rpms'.format(major_ver))
    disable_repos('rhel-{0}-server-satellite-6.0-rpms'.format(major_ver))
    # Add Sat6 repo from latest compose
    satellite_repo = StringIO()
    satellite_repo.write('[sat6]\n')
    satellite_repo.write('name=satellite 6\n')
    satellite_repo.write('baseurl={0}\n'.format(base_url))
    satellite_repo.write('enabled=1\n')
    satellite_repo.write('gpgcheck=0\n')
    put(local_path=satellite_repo, remote_path='/etc/yum.repos.d/sat6.repo')
    satellite_repo.close()
    # Stop katello services, except mongod
    run('katello-service stop')
    run('service-wait mongod start')
    # yum cleaning all
    run('yum clean all', warn_only=True)
    # Updating the packages again after setting sat6 repo
    update_packages(quiet=True)
    # Upgrading Katello installer
    run('katello-installer --upgrade')
    # Test the Upgrade is successful
    run('hammer -u admin -p {0} ping'.format(admin_password))


def product_upgrade(product, instance_name, image_name, flavor_name, ssh_key):
    """Task which upgrades the product.

    Product is satellite.

    :param product: A string. product name wanted to upgrade
    :param instance_name: A string. Openstack Instance name
        onto which upgrade will run.
    :param image_name: A string. Openstack image name
        from which instance to create.
    :param flavor_name: A string. Openstack flavor_name for instance to create.
        e.g m1.small.
    :param ssh_key: A string. ssh_key 'name' that is required
        to add into this instance.

    The following environment variables affect this command:

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

    Note: ssh_key should be added to openstack project before
    running automation, else the automation will fail.

    """
    upgrade_tasks = {'satellite': satellite6_upgrade}
    product = product.lower()
    products = upgrade_tasks.keys()

    if product not in products:
        print ('Product name should be one of {0}'.format(', '.join(products)))
        sys.exit(1)
    execute(delete_openstack_instance, instance_name)
    execute(
        create_openstack_instance,
        instance_name,
        image_name,
        flavor_name,
        ssh_key
    )
    # Getting the host name on to which upgrade will run
    host = env.get('instance_host')
    execute(upgrade_tasks[product], host=host)
