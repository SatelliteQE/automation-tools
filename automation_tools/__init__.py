"""A set of tasks for automating interactions with Satellite servers.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.

"""
from __future__ import print_function
import os
import random
import requests
import socket
import sys
import time
import novaclient
import subprocess
from datetime import date
from lxml import html
from re import search
from urlparse import urlsplit

from automation_tools.satellite6.capsule import generate_capsule_certs
from automation_tools.repository import (
    delete_custom_repos, enable_satellite_repos, enable_repos, disable_repos)
from automation_tools.utils import distro_info, update_packages
from fabric.api import cd, env, execute, get, local, put, run, settings, sudo
from novaclient.client import Client

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
    fix_hostname(entry_domain, host_ip)
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
        # Delete EPEL repo files
        delete_custom_repos('epel*')

    run('groupadd docker', warn_only=True)
    run('usermod -aG docker foreman')

    # SElinux workaround let us use ``http://localhost:2375`` for a
    # ``Docker`` Compute Resurce.
    run('sed -i -e "s|^{0}=.*|{0}=\'{1}\'|" /etc/sysconfig/docker'.format(
        'OPTIONS' if os_version >= 7 else 'other_args',
        ' '.join([
            '--selinux-enabled=true',
            '--host tcp://0.0.0.0:2375',
            '--host unix:///var/run/docker.sock',
            '-G docker',
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

        # Ignore errors related to infiniband if any and just fetch
        # virtual bridge information.
        interface = run(
            'ifconfig 2> /dev/null | grep virbr | awk \'{print $1}\''
        )
        # Always select the first interface
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

    if 'DHCP_RANGE' in os.environ:
        installer_options['capsule-dhcp-range'] = os.environ.get('DHCP_RANGE')

    if 'GATEWAY' in os.environ:
        gateway = os.environ.get('GATEWAY')
        installer_options['capsule-dhcp-gateway'] = gateway
        zone = gateway.rpartition('.')[0]
        reversed_zone = '.'.join(reversed(zone.split('.')))
        dns_reverse_zone = '{0}.in-addr.arpa'.format(reversed_zone)
        installer_options['capsule-dns-reverse'] = dns_reverse_zone

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


def setup_oscap():
    """Task to setup oscap on foreman."""
    # Check if ruby193-rubygem-foreman_openscap package is available
    result = run('yum list ruby193-rubygem-foreman_openscap', quiet=True)
    if result.failed:
        print('WARNING: OSCAP was not set up')
        return

    # Install required packages for the installation
    packages = [
        'rubygem-smart_proxy_openscap',
        'ruby193-rubygem-foreman_openscap'
    ]
    for package in packages:
        run('yum install -y {0}'.format(package))

    for daemon in ('foreman', 'httpd', 'foreman-proxy'):
        manage_daemon('restart', daemon)


def install_puppet_scap_client():
    """Task to setup puppet-foreman_scap_client."""
    run('yum -y install puppet-foreman_scap_client', warn_only=True)


def setup_foreman_discovery():
    """Task to setup foreman discovery."""
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    template_url = os.environ.get('PXE_DEFAULT_TEMPLATE_URL')
    if template_url is None:
        print('You must specify the PXE default template URL')
        sys.exit(1)

    template_file = run('mktemp')
    hostname = run('hostname -f', quiet=True).strip()
    run('yum -y install foreman-discovery-image', warn_only=True)
    run('wget -O {0} {1}'.format(template_file, template_url))
    run('sed -i -e "s/SatelliteCapsule_HOST/{0}/" {1}'
        .format(hostname, template_file))
    run('hammer -u admin -p {0} template update --name '
        '"PXELinux global default" --file {1}'
        .format(admin_password, template_file))
    run('rm -rf {0}'.format(template_file))


def setup_libvirt_key():
    """Task to setup key pairs and verify host for secure communication between
    Satellite server and libvirt hypervisor (qemu+ssh).

    Expects the following environment variables:

    LIBVIRT_HOSTNAME
        hostname of libvirt hypervisor machine
    LIBVIRT_KEY_URL
        URL of relevant SSH key used for authentication to libvirt machine
    """
    root_key_file = '/root/.ssh/id_rsa'
    foreman_key_file = '~/foreman/.ssh/id_rsa'
    key_url = os.environ.get('LIBVIRT_KEY_URL')
    libvirt_host = os.environ.get('LIBVIRT_HOSTNAME')

    if key_url is None or libvirt_host is None:
        print('You must specify the Libvirt key URL and the Libvirt hostname')
        sys.exit(1)
    # Deploy priv ssh key under root and foreman account
    run('wget -O {0} {1}'.format(root_key_file, key_url))
    run('chmod 600 {0}'.format(root_key_file))
    sudo('wget -O {0} {1}'.format(foreman_key_file, key_url), user='foreman')
    sudo('chmod 600 {0}'.format(foreman_key_file), user='foreman')
    # Add libvirt host into known hosts
    with settings(prompts={
        'Are you sure you want to continue connecting (yes/no)? ': 'yes'}
    ):
        run('ssh {0} date'.format(libvirt_host), warn_only=True)
        sudo(
            'ssh root@{0} date'.format(libvirt_host), user='foreman',
            warn_only=True
        )


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
    BRIDGE
        Now Sat6 VM can use isolated VLAN Bridge with static Ip address if
        available, otherwise uses the bridge br0 which provides a dhcp IP
        address from corporate network.
    IPADDR
        The static IP address from the VLAN which needs to be provided when
        using VLAN Bridge.
    NETMASK
        The static netmask of the VLAN when using VLAN Bridge
    GATEWAY
        The static gateway of the VLAN when using VLAN Bridge

    If the Bridge being used is br0 then a DHCP IP is used and the VM will have
    the TARGET_IMAGE.VM_DOMAIN hostname, but make sure to have setup DDNS entry
    correctly.

    Alternately if a VLAN Bridge is being used the VM will be assigned static
    IP address and the VM will have a fixed domain name and no need to
    configure DDNS.

    Why does Satellite6 VM require a static IP address?
    Because to provision vms on existing rhevm and external Libvirt instances.

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
        'bridge': os.environ.get('BRIDGE'),
        'ip_addr': os.environ.get('IPADDR'),
        'netmask': os.environ.get('NETMASK'),
        'gateway': os.environ.get('GATEWAY'),
    }

    command_args = [
        'snap-guest',
        '-b {source_image}',
        '-t {target_image}',
        '-m {vm_ram}',
        '-c {vm_cpu}',
        '-d {vm_domain} -f',
    ]

    if options['image_dir'] is not None:
        command_args.append('-p {image_dir}')

    if options['cpu_feature'] is not None:
        command_args.append('--cpu-feature {cpu_feature}')

    if options['bridge'] is not None:
        command_args.append('-n bridge={bridge}')
    else:
        command_args.append('-n bridge=br0')

    if options['ip_addr'] is not None:
        command_args.append('--static-ipaddr {ip_addr}')

    if options['netmask'] is not None:
        command_args.append('--static-netmask {netmask}')

    if options['gateway'] is not None:
        command_args.append('--static-gateway {gateway}')

    command = ' '.join(command_args).format(**options)
    run(command)

    # Give some time to machine boot
    time.sleep(60)

    # Fetch Ip information via ping only when not using VLAN Bridges as we
    # know the VM's Ip address beforehand.
    if options['bridge'] is None:
        result = run('ping -c 1 {0}.local'.format(
            options['target_image']))
        env['vm_ip'] = result.split('(')[1].split(')')[0]
    else:
        env['vm_ip'] = '{ip_addr}'.format(**options)
    env['vm_domain'] = '{target_image}.{vm_domain}'.format(**options)

    # fix_hostname only if using VLAN Bridge.
    if os.environ.get('BRIDGE'):
        # We need to fix the /etc/hosts file for snap-guest changes.
        execute(
            fix_hostname,
            entry_domain=env['vm_domain'],
            host_ip=env['vm_ip'],
            host=env['vm_ip'],
        )


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

    # Check for virtualization support
    result = run('grep -E "^flags.*(vmx|svm)" /proc/cpuinfo', quiet=True)
    if result.failed:
        print('Virtualization is not supported on this machine')
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
        admin_password=None, check_gpg_signatures=False,
        run_katello_installer=True):
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
    CHECK_GPG_SIGNATURES
       Optional, all values other than 'true' will default to 'false'.

    """
    iso_url = os.environ.get('ISO_URL') or os.environ.get('BASE_URL')
    if iso_url is None:
        print('Please provide a valid URL for the ISO image.')
        sys.exit(1)

    if isinstance(check_gpg_signatures, str):
        check_gpg_signatures = (check_gpg_signatures.lower() == 'true')

    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    check_gpg_signatures = (
        check_gpg_signatures or
        os.environ.get('CHECK_GPG_SIGNATURES', '') == 'true'
    )

    # Download the ISO
    iso_download(iso_url)

    # Create a 'check-out' folder, mount ISO to it...
    run('mkdir ISO')
    run('mount *.iso ISO -t iso9660 -o loop')
    # ...and run the installer script.
    with cd('/root/ISO'):
        if check_gpg_signatures is True:
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
                    selinux_mode=None, sat_cdn_version=None,
                    test_in_stage=False):
    """Task which install every product distribution.

    Product distributions are sam-upstream, satellite6-cdn,
    satellite6-downstream, satellite6-iso or satellite6-upstream.

    If ``create_vm`` is True then ``vm_destroy`` and ``vm_create`` tasks will
    be run. Make sure to set the required environment variables for those
    tasks.
    Also, if one of the ``setup_ddns`` required environment variables
    is set then that task will only run if the VM does not use any VLAN Bridges

    If ``certificate_url`` parameter or ``FAKE_MANIFEST_CERT_URL`` env var is
    defined the setup_fake_manifest_certificate task will run.

    Every call to a task after the definition ``host = env.get('vm_ip',
    env['host'])`` must be run by using ``execute`` and passing ``host=host``.

    :param str distribution: product distribution wanted to install
    :param bool create_vm: creates a virtual machine and then install the
        product on it. Default: False.
    :param str certificate_url: where to fetch a fake certificate.

    """
    # Command-line arguments are passed in as strings.
    if isinstance(create_vm, str):
        create_vm = (create_vm.lower() == 'true')
    if isinstance(test_in_stage, str):
        test_in_stage = (test_in_stage.lower() == 'true')

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

    if (distribution == 'satellite6-cdn' and
            sat_cdn_version not in ('6.0', '6.1')):
        raise ValueError("Satellite version should be either 6.0 or 6.1")

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

        # Execute setup_ddns only if not using VLAN Bridges.
        if os.environ.get('BRIDGE') is None:
            if 'DDNS_HASH' in os.environ or 'DDNS_PACKAGE_URL' in os.environ:
                execute(
                    setup_ddns,
                    env['vm_domain'],
                    env['vm_ip'],
                    host=env['vm_ip']
                )

    # When creating a vm the vm_ip will be set, otherwise use the fabric host
    host = env.get('vm_ip', env['host'])

    # Register and subscribe machine to Red Hat
    if distribution == 'satellite6-cdn' and test_in_stage:
        execute(update_rhsm_stage, host=host)
    execute(subscribe, host=host)

    execute(install_prerequisites, host=host)
    execute(setenforce, selinux_mode, host=host)
    execute(
        enable_satellite_repos,
        cdn=distribution.endswith('cdn'),
        beta=distribution.endswith('beta'),
        cdn_version=sat_cdn_version,
        host=host
    )

    # Update the machine
    execute(update_packages, host=host, warn_only=True)

    if distribution in ('satellite6-downstream', 'satellite6-iso'):
        execute(java_workaround, host=host)
    # execute returns a dictionary mapping host strings to the given task's
    # return value
    installer_options.update(execute(
        install_tasks[distribution], host=host, run_katello_installer=False
    )[host])

    if distribution in (
            'satellite6-cdn', 'satellite6-downstream', 'satellite6-iso'):
        # When using VLAN Bridges os.environ.get('BRIDGE') is 'true' and
        # executes with 'interface=eth0' for Satellite6-automation.
        # When using Satellite6-installer one can specify custom interface.
        if os.environ.get('BRIDGE') or os.environ.get('INTERFACE'):
            # execute returns a dictionary mapping host strings to the given
            # task's return value
            installer_options.update(execute(
                setup_default_capsule,
                host=host,
                # If an INTERFACE is specified it will be used otherwise would
                # default to eth0 interface. Helpful for configuring DHCP and
                # DNS capsule services.
                interface=os.environ.get('INTERFACE') or 'eth0',
                run_katello_installer=False
            )[host])
        else:
            # execute returns a dictionary mapping host strings to the given
            # task's return value.
            installer_options.update(execute(
                setup_default_capsule, host=host, run_katello_installer=False
            )[host])

    # Firewall should be setup after setup_default_capsule clean the puppet
    # module it installs clean already created rules
    execute(setup_firewall, host=host)

    if distribution.startswith('satellite6'):
        if os.environ.get('PROXY_INFO'):
            # execute returns a dictionary mapping host strings to the given
            # task's return value
            installer_options.update(execute(
                setup_proxy, host=host, run_katello_installer=False
            )[host])

    if os.environ.get('INSTALLER_OPTIONS'):
        # INSTALLER_OPTIONS are comma separated katello-installer options.
        # It will be of the form "key1=val1,key2=val2".
        ins_opt = os.environ.get('INSTALLER_OPTIONS')
        ins_opt_dict = dict(i.split('=') for i in ins_opt.split(','))
        installer_options.update(ins_opt_dict)

    execute(
        katello_installer,
        host=host,
        sam=distribution.startswith('sam'),
        **installer_options
    )

    if distribution.startswith('satellite6'):
        execute(setup_default_docker, host=host)
        execute(katello_service, 'restart', host=host)
        if not distribution.endswith('upstream'):
            if os.environ.get('PXE_DEFAULT_TEMPLATE_URL') is not None:
                execute(setup_foreman_discovery, host=host)
            if os.environ.get('LIBVIRT_KEY_URL') is not None:
                execute(setup_libvirt_key, host=host)
            execute(install_puppet_scap_client, host=host)
            execute(setup_oscap, host=host)

    certificate_url = certificate_url or os.environ.get(
        'FAKE_MANIFEST_CERT_URL')
    if certificate_url is not None:
        execute(
            setup_fake_manifest_certificate,
            certificate_url,
            host=host
        )

    execute(fix_qdrouterd_listen_to_ipv6, host=host)


def fix_qdrouterd_listen_to_ipv6():
    """Configure qdrouterd to listen to IPv6 instead of IPv4.

    Workaround for BZ #1219902.

    """
    run('sed -i -e "0,/addr: 0.0.0.0/s/addr: 0.0.0.0/addr: ::/" '
        '/etc/qpid-dispatch/qdrouterd.conf')
    manage_daemon('restart', 'qdrouterd')


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


def fix_hostname(entry_domain=None, host_ip=None):
    """Updates `/etc/hosts` with FQDN and IP."""
    if host_ip and entry_domain:
        # Required when running product-automation.
        host = entry_domain.split('.', 1)[0]
        run('echo "127.0.0.1 {0} localhost" > /etc/hosts'.format(entry_domain))
        run('echo "{0} {1} {2}" >> /etc/hosts'
            .format(host_ip, entry_domain, host))
    else:
        # Required for fixing the hostname when using satellite-installer
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

def update_rhsm_stage():
    """Updates the host to point to stage

    The following environment variables affect this command:

    RHN_STAGE_SERVER
        Stage content server
    CDN_STAGE_URL
        Stage content baseurl

    """
    rhn_stage_server = os.environ.get('RHN_STAGE_SERVER')
    cdn_stage_url = os.environ.get('CDN_STAGE_URL')
    if rhn_stage_server is None or cdn_stage_url is None:
        print('RHN_STAGE and CDN_STAGE_URL are required to continue')
        sys.exit(1)
    run("sed -i -e 's/^hostname.*/hostname={0}/' "
        "/etc/rhsm/rhsm.conf".format(rhn_stage_server))
    run("sed -i -e 's|^baseurl.*|baseurl={0}|' "
        "/etc/rhsm/rhsm.conf".format(cdn_stage_url))
    manage_daemon('restart', 'rhsmcertd')


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


def client_registration_test(clean_beaker=True, update_package=True,
                             product_type=None, reset_system=True):
    """Register client against Satellite 6 and run tests.

    :param clean_beaker: Clean beaker repositories if ``True``.
    :param update_package: Update the host with latest packages if ``True``.
    :param product_type: Set the product type. Legal values:

        ``None``
            default
        ``compute``
            for compute products
        ``desktop``
            for desktop products

    :param reset_system: Reset the subscription management back to RHSM.

    Affected by the following environment variables:

        ``ORG``
            (Optional) Org to register.  Default is Default_Organization
        ``ACTIVATIONKEY``
            (Mandatory) Activation key to register
        ``CERTURL``
            (Mandatory) The server cert url to install
        ``RELVER``
            (Optional) Release version to register

    """
    # Since all arguments are turned to string, if no defaults are
    # used...
    if isinstance(clean_beaker, str):
        clean_beaker = (clean_beaker.lower() == 'true')
    if isinstance(update_package, str):
        update_package = (update_package.lower() == 'true')

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
    # Release version for the client - Optional - no need to error out if not
    # available
    rel_ver = os.getenv('RELVER')
    # If this is a Beaker box, 'disable' Beaker repos
    if clean_beaker is True:
        run('mv /etc/yum.repos.d/beaker* .', warn_only=True)

    # Update some basic packages before we try to register
    if update_package is True:
        update_basic_packages()

    # Install the cert file
    run('rpm -Uvh {0}'.format(cert_url), warn_only=True)

    # Register and subscribe
    print('Register/Subscribe using Subscription-manager.')
    cmd = (
        'subscription-manager register --force --org="{0}" '
        '--activationkey="{1}"'.format(org, act_key)
    )
    if rel_ver:
        cmd += ' --release="{0}"'.format(rel_ver)
    run(cmd)
    print('Refreshing Subscription-manager.')
    run('subscription-manager refresh')
    print('Performing yum clean up.')
    run('yum clean all', quiet=True)

    # Checking Package installation
    print('"Firefox" and "Telnet" should not be installed.')
    run('rpm -q firefox telnet', warn_only=True)
    print('Installing "Telnet".')
    result = run('yum install -y telnet', quiet=True)
    if result.succeeded:
        print('"Telnet" is installed.')
    run('rpm -q telnet')  # This will fail if telnet is not installed
    print('Removing "Telnet".')
    run('yum remove -y telnet', quiet=True)
    print('Checking if "Telnet" is installed.')
    run('rpm -q telnet', warn_only=True)

    # Firefox is not available in compute product
    if product_type != 'compute':
        print('Installing "Firefox"')
        result = run('yum install -y firefox', quiet=True)
        if result.succeeded:
            print('"Firefox" is installed.')
        run('rpm -q firefox')  # This will fail if firefox is not installed
        print('Removing "Firefox"')
        run('yum remove -y firefox', quiet=True)
        print('Checking if "Firefox" is installed.')
        run('rpm -q firefox ', warn_only=True)

    # Group packages differ depending on the rhel product variance
    if product_type is None:
        # This is the default behavior if product_type is not passed
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
    elif product_type == 'desktop':
        # For desktop products install Networking Tools
        print('Installing "Networking Tools" group.')
        run('yum groupinstall -y "Networking Tools"', quiet=True)
        print('Checking for "nc" package.')
        run('rpm -q nc')
        print('Remove "Networking Tools" group.')
        run('yum groupremove -y "Networking Tools"', quiet=True)
        print('Checking if "nc" is really removed.')
        run('rpm -q nc', warn_only=True)
    elif product_type == 'compute':
        # For compute products install PostgreSQL Database client
        print('Installing "PostgreSQL Database client" group.')
        run('yum groupinstall -y "PostgreSQL Database client"', quiet=True)
        print('Checking for "postgresql" package.')
        run('rpm -q postgresql')
        print('Remove "PostgreSQL Database client" group.')
        run('yum groupremove -y "PostgreSQL Database client"', quiet=True)
        print('Checking if "postgresql" is really removed.')
        run('rpm -q postgresql', warn_only=True)
    # Install random errata
    install_errata()
    print('Listing yum history for verification.')
    run('yum history list')
    # Clean up
    if reset_system is True:
        # 'reset_system' input parameter should be set to false if registration
        # should be persisted after testing.  Default is True so as to test
        # the unregister feature
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


def katello_installer(debug=False, sam=False, verbose=True, **kwargs):
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


def katello_service(action, exclude=None):
    """Run katello-service

    :param str action: One of stop, start, restart, status.
    :param list exclude: A list of services to skip

    """
    if exclude is None:
        exclude = ''
    else:
        exclude = '--exclude {}'.format(','.join(exclude))
    return run('katello-service {} {}'.format(exclude, action))


def manage_daemon(action, daemon, pty=True, warn_only=False):
    """Manage a system daemon

    :param str action: Daemon action like start, stop, restart, info
    :param str daemon: Daemon name to perform the action
    :param bool pty: Controls the creation of a pseudo-terminal when managing
        the daemon. Some daemons actions fail with pty=True.
    :param bool warn_only: Will be passed directly to Fabric's run

    """
    if distro_info()[1] >= 7:
        command = 'systemctl {0} {1}'.format(action, daemon)
    else:
        if action in ('enable', 'disable'):
            command = 'chkconfig {0} {1}'.format(
                daemon,
                'on' if action == 'enable' else 'off'
            )
        else:
            command = 'service {0} {1}'.format(daemon, action)
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
    """This syncs capsule and sat-tools repos in Satellite server.

    Useful for upgrading Capsule and Client in feature.

    :param admin_password: A string. Defaults to 'changeme'.
        Foreman admin password for hammer commands.

    Following environment variable affects this function:

    CAPSULE_URL
        The url for capsule repo from latest satellite compose.
    TOOLS_URL
        The url for sat-tools repo from latest satellite compose.
    FROM_VERSION:
        Current Satellite version - to differentiate default organization.
        e.g. '6.1', '6.0'

    """
    if os.environ.get('FROM_VERSION') == '6.1':
        org = '\'Default Organization\''
    elif os.environ.get('FROM_VERSION') == '6.0':
        org = 'Default_Organization'
    else:
        print('Wrong FROM_VERSION Provided. Provide one of 6.1 or 6.0...')
        sys.exit(1)
    capsule_repo = os.environ.get('CAPSULE_URL')
    tools_repo = os.environ.get('TOOLS_URL')
    version = distro_info()[1]
    if capsule_repo is None:
        print('The Capsule repo URL is not provided '
              'to perform Capsule Upgrade in feature!')
        sys.exit(1)
    if tools_repo is None:
        print('The Satellite Tools repo URL is not provided '
              'to perform Client Upgrade in feature!')
        sys.exit(1)
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    initials = 'hammer -u admin -p {0} '.format(admin_password)
    # First initiate the connection with capsule by syncing it
    capsule_id = str(
        run(initials + 'capsule list | grep {0}'.format(
            env.get('capsule_host')))).split('|')[0].strip()
    run(initials+'capsule content synchronize --id {0}'.format(capsule_id))
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
    # Create product sattools
    run(initials + 'product create --name satTools6_latest '
        '--organization {0}'.format(org))
    time.sleep(2)
    tools_sub_id = str(
        run(initials + 'subscription list '
            '--organization {0} | grep satTools6_latest'.format(org))
    ).split('|')[7].strip()
    # Create repo satools
    run(initials + 'repository create --content-type yum '
        '--name satTools6_latest_repo --label satTools6_latest_repo '
        '--product satTools6_latest --publish-via-http true --url {0} '
        '--organization {1}'.format(tools_repo, org))
    # Sync repos
    run(initials + 'repository synchronize --name capsule6_latest_repo '
        '--product capsule6_latest --organization {0}'.format(org))
    run(initials + 'repository synchronize --name satTools6_latest_repo '
        '--product satTools6_latest --organization {0}'.format(org))
    run(initials + 'content-view list --organization {0} | '
        'grep rhel'.format(org))
    capsule_repo_id = str(
        run(initials + 'repository list --organization {0} | '
            'grep capsule6_latest_repo'.format(org))).split('|')[0].strip()
    tools_repo_id = str(
        run(initials + 'repository list --organization {0} | '
            'grep satTools6_latest_repo'.format(org))).split('|')[0].strip()
    # Add repos to CV
    run(initials + 'content-view add-repository --name rhel{0}_cv '
        '--repository-id {1} --organization {2}'.format(
            version, capsule_repo_id, org))
    run(initials + 'content-view add-repository --name rhel{0}_cv '
        '--repository-id {1} --organization {2}'.format(
            version, tools_repo_id, org))
    # publish cv
    run(initials + 'content-view publish --name rhel{0}_cv '
        '--organization {1}'.format(version, org))
    # promote cv
    lc_env_id = str(
        run(initials + 'lifecycle-environment list '
            '--organization {0} | grep DEV'.format(org))).split(
                '|')[0].strip()
    cv_ver_id = str(
        run(initials + 'content-view version list --content-view rhel{0}_cv '
            '--organization {1} | grep rhel'.format(
                version, org))).split('|')[0].strip()
    run(initials + 'content-view version promote --content-view rhel{0}_cv '
        '--id {1} --lifecycle-environment-id {2} --organization '
        '{3}'.format(version, cv_ver_id, lc_env_id, org))
    ak_id = str(
        run(initials + 'activation-key list --organization '
            '{0} | grep rhel'.format(org))).split('|')[0].strip()
    # Add new product subscriptions to AK
    run(initials + 'activation-key add-subscription --id {0} --quantity 1 '
        '--subscription-id {1}'.format(ak_id, capsule_sub_id))
    run(initials + 'activation-key add-subscription --id {0} --quantity 1 '
        '--subscription-id {1}'.format(ak_id, tools_sub_id))
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
    update_packages(quiet=True)
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
    update_packages(quiet=True)
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
        product, ssh_key, sat_instance, sat_image, sat_flavor,
        cap_instance=None, cap_image=None, cap_flavor=None):
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

    Note: ssh_key should be added to openstack project before
    running automation, else the automation will fail.

    """
    products = ['satellite', 'capsule']
    if product not in products:
        print ('Product name should be one of {0}'.format(', '.join(products)))
        sys.exit(1)
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
    execute(subscribe, host=sat_host)
    # Rebooting the services
    execute(lambda: run('katello-service restart'), host=sat_host)
    # For Capsule Upgrade
    if product == 'capsule':
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
        # Copy ssh key from satellie to capsule
        copy_ssh_key(sat_host, cap_host)
        if os.environ.get('CAPSULE_URL') is not None:
            execute(sync_capsule_tools_repos_to_upgrade, host=sat_host)
    # Run satellite upgrade
    execute(satellite6_upgrade, host=sat_host)
    # Generate foreman debug on satellite
    execute(foreman_debug, 'satellite', host=sat_host)
    if product == 'capsule':
        print('\nRunning Capsule Upgrade ..........')
        # Run capsule upgrade
        execute(satellite6_capsule_upgrade, host=cap_host)
        # Generate foreman debug on capsule
        execute(foreman_debug, 'capsule', host=cap_host)


def idp_authenticate(idp=None):
    """Authenticates on a customer portal and returns a session object.

    The following environment variables affect this command:

    IDP_URL
        Identity Provider URL
    RHN_USERNAME
        Red Hat Network username
    RHN_PASSWORD
        Red Hat Network password
    :param idp: id provider url (typically https://idp.redhat.com/idp/)
    :returns: A requests.Session instance containing IDP session cookies
    """
    if idp is None:
        idp = os.environ.get('IDP_URL')
    user = os.environ.get('RHN_USERNAME')
    password = os.environ.get('RHN_PASSWORD')

    session = requests.session()
    session.get(idp)
    idp_request = session.post(
        '{}/j_security_check'.format(idp),
        data={
            u'j_username': user,
            u'j_password': password,
        }
    )
    idp_tree = html.fromstring(idp_request.text)
    try:
        ugc_url = idp_tree.xpath(
            '//div[@class="loginBox"]/table/center/a'
        )[0].get('href')
    except IndexError:
        print('Unable to find UGC link in the returned HTML.'
              'Check IDP url and credentials')
        sys.exit(1)

    ugc_request = session.get(
        ugc_url
    )
    ugc_tree = html.fromstring(ugc_request.text)
    try:
        action_url = ugc_tree.xpath('//form[@method="POST"]')[0].get('action')
        saml_hash = ugc_tree.xpath(
            '//input[@name="SAMLRequest"]'
        )[0].get('value')
        relay_hash = ugc_tree.xpath(
            '//input[@name="RelayState"]'
        )[0].get('value')
    except:
        print('Error during parsing the values from the returned HTML.'
              'The authentication procedure might have changed')
        sys.exit(1)
    ugc2_request = session.post(
        action_url,
        data={
            u'SAMLRequest': saml_hash,
            u'RelayState': relay_hash,
        }
    )
    ugc2_tree = html.fromstring(ugc2_request.text)
    try:
        action_url_2 = ugc2_tree.xpath(
            '//form[@method="POST"]'
        )[0].get('action')
        saml2_hash = ugc2_tree.xpath(
            '//input[@name="SAMLResponse"]'
        )[0].get('value')
        relay2_hash = ugc2_tree.xpath(
            '//input[@name="RelayState"]'
        )[0].get('value')
    except:
        print('Error during parsing the values from the returned HTML.'
              'The authentication procedure might have changed')
        sys.exit(1)
    auth_request = session.post(
        action_url_2,
        data={
            u'SAMLResponse': saml2_hash,
            u'RelayState': relay2_hash,
        }
    )
    if auth_request.ok is True:
        return session
    else:
        auth_request.raise_for_status()


def download_manifest(url=None, session=None, distributor=None):
    """Task for downloading the manifest file from customer portal.

    The following environment variables affect this command:

    CUSTOMER_PORTAL_URL
        Customer Portal URL (typically 'https://access.redhat.com')
    DISTRIBUTOR
        A distributor hash to be used for getting the manifest

    :param url: Customer Portal URL (typically 'https://access.redhat.com')
    :param session: A requests.session object with a valid customer portal
        session
    :param distributor: A distributor hash to be used for getting the manifest
    :returns: a path string to a downloaded manifest file
    """
    if url is None:
        url = os.environ.get('CUSTOMER_PORTAL_URL')
    if session is None:
        session = idp_authenticate()
    if distributor is None:
            distributor = os.environ.get('DISTRIBUTOR')
    manifest_file = run('mktemp --suffix=.zip')
    headers = ''
    for cookie in session.cookies:
        headers += '{0}={1}; '.format(cookie.name, cookie.value)
    response = run(
        'curl -sIb \'{0}\' {1}/management/distributors/{2}/certificate/'
        'manifestdownload'
        .format(headers, url, distributor, manifest_file))
    if ('Content-Disposition: attachment' in response and
            distributor in response):
        run('curl -sb \'{0}\' -o {3} {1}/management/distributors/{2}/'
            'certificate/manifestdownload'
            .format(headers, url, distributor, manifest_file)
            )
        return manifest_file
    else:
        raise ValueError('Request has returned no attachment. Check the'
                         ' session and distributor hash')


def relink_manifest(manifest_file=None):
    """Links the latest downloaded manifest file to the manifest_latest.zip
    softlink.

    :param manifest_file: Specify the manifest file path.
    """
    if manifest_file is None:
        manifest_file = download_manifest()
    if not manifest_file:
        print('manifest_file is not populated.')
        sys.exit(1)
    date_str = date.today().strftime("%Y%m%d")
    new_manifest_file = '/opt/manifests/manifest-{0}.zip'.format(date_str)
    run('mv {0} {1}'.format(manifest_file, new_manifest_file))
    run('chmod 644 {0}'.format(new_manifest_file))
    run('restorecon -v {0}'.format(new_manifest_file))
    run('unlink /opt/manifests/manifest-latest.zip')
    run('ln -s {0} /opt/manifests/manifest-latest.zip'
        .format(new_manifest_file))
