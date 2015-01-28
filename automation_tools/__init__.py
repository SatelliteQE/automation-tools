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
from re import search
from urlparse import urlsplit

from fabric.api import cd, env, execute, local, put, run
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
    distro, major_version, minor_version = distro_info()
    if distro.lower() != 'rhel':
        return

    # Register the system.
    for env_var in ('RHN_USERNAME', 'RHN_PASSWORD'):
        if env_var not in os.environ:
            print('The {0} environment variable must be set.'.format(env_var))
            sys.exit(1)
    if minor_version is None:
        minor_version = 'Server'
    else:
        minor_version = '.{0}'.format(minor_version)
    run(
        'subscription-manager register --force --user={0} --password={1} '
        '--release="{2}{3}" {4}'
        .format(
            os.environ['RHN_USERNAME'],
            os.environ['RHN_PASSWORD'],
            major_version,
            minor_version,
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
            if result.return_code is 0 or has_pool_msg in result:
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


def setup_proxy():
    """Task to setup a proxy and block non-proxy traffic from your foreman
    server.

    Proxy information is passed using the PROXY_INFO environmental variable.
    e.g. PROXY_INFO=proxy://root:myP4$$@myhost.awesomedomain.com:8888
    """

    os_version = distro_info()[1]

    proxy_info = urlsplit(os.environ.get('PROXY_INFO'))
    if not proxy_info.hostname or not proxy_info.port:
        raise Exception("You must include the proxy hostname and port.")

    # Configure pulp to use the proxy (ref BZ1114083)
    proxy_json = (
        '{{'
        '    "proxy_host": "http://{0}", '
        '    "proxy_port": {1}, '
        '    "proxy_username": "{2}", '
        '    "proxy_password": "{3}"'
        '}}'
        .format(proxy_info.hostname, proxy_info.port,
                proxy_info.username, proxy_info.password)
    )

    # write the json to the appropriate files
    run("echo '{0}' | tee {1} {2} {3}".format(
        proxy_json,
        '/etc/pulp/server/plugins.conf.d/iso_importer.json',
        '/etc/pulp/server/plugins.conf.d/puppet_importer.json',
        '/etc/pulp/server/plugins.conf.d/yum_importer.json'
        ))

    # restart the capsule-related services
    daemons = (
        'httpd', 'pulp_celerybeat', 'pulp_resource_manager', 'pulp_workers',
    )
    if os_version >= 7:
        run('systemctl restart {0}'.format(' '.join(daemons)), warn_only=True)
        run('yum install -y iptables-services')  # Install firewall package
    else:
        for daemon in daemons:
            run('service {0} restart'.format(daemon), warn_only=True)

    # Satellite 6 IP
    sat_ip = search(
        r'\d+ bytes from (.*):',
        run('ping -c 1 -n $(hostname) | grep "icmp_seq"')
    ).group(1)
    run('iptables -I OUTPUT -d {0} -j ACCEPT'.format(sat_ip))

    # PROXY IP
    proxy_ip = search(
        r'\d+ bytes from (.*):',
        run('ping -c 1 -n {0} | grep "icmp_seq"'.format(proxy_info.hostname))
    ).group(1)
    run('iptables -I OUTPUT -d {0} -j ACCEPT'.format(proxy_ip))

    # Nameservers
    nameservers = run(
        'cat /etc/resolv.conf | grep nameserver | cut -d " " -f 2')
    for entry in nameservers.split('\n'):
        run('iptables -I OUTPUT -d {0} -j ACCEPT'.format(entry.strip()))

    # To make the changes persistent across reboots when using the command line
    # use this command:
    run('iptables-save > /etc/sysconfig/iptables')

    if os_version >= 7:
        # rhel7 replaced iptables with firewalld
        run('systemctl enable iptables')
        run('systemctl restart iptables', warn_only=True)
    else:
        run('service iptables restart')

    # Configuring yum to use the proxy
    run('echo "proxy=http://{0}:{1}" >> /etc/yum.conf'
        .format(proxy_info.hostname, proxy_info.port))
    run('echo "proxy_username={0}" >> /etc/yum.conf'
        .format(proxy_info.username))
    run('echo "proxy_password={0}" >> /etc/yum.conf'
        .format(proxy_info.password))

    # Configuring rhsm to use the proxy
    run('sed -i -e "s/^proxy_hostname.*/proxy_hostname = {0}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.hostname))
    run('sed -i -e "s/^proxy_port.*/proxy_port = {0}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.port))
    run('sed -i -e "s/^proxy_user.*/proxy_user = {0}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.username))
    run('sed -i -e "s/^proxy_password.*/proxy_password = {0}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.password))

    # Run the installer
    run('katello-installer -v --foreman-admin-password="changeme" '
        '--katello-proxy-url=http://{0} --katello-proxy-port={1} '
        '--katello-proxy-username={2} '
        '--katello-proxy-password={3}'.format(
            proxy_info.hostname, proxy_info.port,
            proxy_info.username, proxy_info.password
        ))


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
    run('usermod -aG docker apache')

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
    if os_version >= 7:
        run('systemctl restart docker')
    else:
        # This can silently fail if a pseuo-terminals is used, due to docker's
        # non-standard approach to daemonizing and its naive init script. See:
        #
        # https://github.com/fabric/fabric/issues/395#issuecomment-1846383
        # https://github.com/fabric/fabric/issues/395#issuecomment-32219270
        # https://github.com/docker/docker/issues/2758
        #
        run('service docker restart', pty=False)

    # Check that things look good
    run('docker ps')

    # Pull down a very simple/light Docker container to 'seed' the
    # system with something that can be used right away.
    run('docker pull busybox')


def setup_default_capsule(interface=None):
    """Task to setup a the default capsule for Satellite

    :param str interface: Network interface name to be used

    """
    forwarders = run('cat /etc/resolv.conf | grep nameserver | '
                     'awk \'{print $2}\'', quiet=True).split('\n')
    forwarders = ' '.join([
        '--capsule-dns-forwarders {0}'.format(forwarder.strip())
        for forwarder in forwarders
    ])
    if len(forwarders) == 0:
        print('Was not possible to fetch nameserver information')
        sys.exit(1)

    oauth_secret = run(
        'grep oauth_consumer_secret /etc/foreman/settings.yaml | '
        'cut -d " " -f 2', quiet=True).strip()
    if len(oauth_secret) == 0:
        print('Not able to')

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
        if distro_info()[1] >= 7:
            run('systemctl enable libvirtd')
            run('systemctl start libvirtd')
        else:
            run('service libvirtd start')
            run('chkconfig libvirtd on')
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

    run(
        'katello-installer -v '
        '--capsule-parent-fqdn {hostname} '
        '--capsule-dns true '
        '{forwarders} '
        '--capsule-dns-interface {interface} '
        '--capsule-dns-zone {domain} '
        '--capsule-dhcp true '
        '--capsule-dhcp-interface {interface} '
        '--capsule-tftp true '
        '--capsule-puppet true '
        '--capsule-puppetca true '
        '--capsule-register-in-foreman true '
        '--capsule-foreman-oauth-secret {oauth_secret}'
        ''.format(
            hostname=hostname,
            forwarders=forwarders,
            interface=interface,
            domain=domain,
            oauth_secret=oauth_secret
        )
    )


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

    os_version = distro_info()[1]

    if os_version <= 6:
        run('service tomcat6 restart')
    else:
        run('systemctl restart tomcat')


def setup_abrt():
    """Task to setup abrt on foreman

    Currently only available on RHEL7, check BZ #1150197 for more info

    """
    # Check if rubygem-smart_proxy_abrt package is available
    result = run(
        'yum list rubygem-smart_proxy_abrt', warn_only=True, quiet=True)
    if result.return_code != 0:
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

    run('systemctl restart foreman')
    # workaround as sometimes foreman service does not restart with systemctl
    run('touch /usr/share/foreman/tmp/restart.txt')

    # edit the config files
    host = env['host']
    run('echo ":foreman_url: https://{0}" >> /etc/foreman-proxy/settings.yml'
        ''.format(host))
    run('sed -i -e "s/^:enabled: false.*/:enabled: true/" '
        '/etc/foreman-proxy/settings.d/abrt.yml')

    # run the required commands
    run('systemctl start abrtd')
    run('systemctl start abrt-ccpp')

    # edit the config files
    run('sed -i -e "s|^URL = .*|URL = https://{0}:8443/abrt/|" '
        '/etc/libreport/plugins/ureport.conf'.format(host))
    run('sed -i -e "|# SSLVerify = no|SSLVerify = yes|" '
        '/etc/libreport/plugins/ureport.conf')
    run('sed -i -e "s|# SSLClientAuth = .*|SSLClientAuth = puppet|" '
        '/etc/libreport/plugins/ureport.conf')
    run('cp /var/lib/puppet/ssl/certs/ca.pem '
        '/etc/pki/ca-trust/source/anchors/')
    run('update-ca-trust')
    run('abrt-auto-reporting enabled')


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

    os_version = distro_info()[1]

    if interface is None:
        print('A network interface is required')
        sys.exit(1)

    # Check for Nested virtualization support
    result = run(
        'grep -E "^Y" /sys/module/kvm_intel/parameters/nested', quiet=True)
    if result.return_code != 0:
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
    if result.return_code != 0:
        print('Virtualization is not supported on this machine')
        sys.exit(1)

    # Install virtualization packages
    run('yum install -y @virtualization')
    run('systemctl start libvirtd')
    run('systemctl enable libvirtd')

    # Install other required packages
    packages = (
        'bash',
        'bridge-utils',
        'cloud-utils',
        'genisoimage',
        'git',
        'kvm',
        'libguestfs-tools',
        'openssl',
        'perl',
        'perl-Sys-Guestfs',
        'python-virtinst',
        'qemu-img',
        'sed',
        'util-linux',
    )
    run('yum install -y {0}'.format(' '.join(packages)))

    # Setup snap-guest
    result = run('[ -d /opt/snap-guest ]', warn_only=True)
    if result.return_code != 0:
        with cd('/opt'):
            run('git clone git://github.com/lzap/snap-guest.git')
        run('sudo ln -s /opt/snap-guest/snap-guest /usr/local/bin/snap-guest')
    else:
        print('Snap-guest already setup, pulling from upstream')
        with cd('/opt/snap-guest'):
            run('git pull')

    # Setup bridge
    result = run(
        '[ -f /etc/sysconfig/network-scripts/ifcfg-br0 ]',
        quiet=True,
        warn_only=True
    )
    if result.return_code != 0:
        # Disable NetworkManager
        if distro_info()[1] >= 7:
            run('systemctl disable NetworkManager')
            run('systemctl stop NetworkManager')
            run('systemctl enable network')
        else:
            run('chkconfig NetworkManager off')
            run('chkconfig network on')
            run('service NetworkManager stop')

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

        if os_version >= 7:
            run('systemctl restart network')
        else:
            run('service network restart')

        # Configure iptables to allow all traffic to be forwarded across the
        # bridge
        run('iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT')
        run('iptables-save > /etc/sysconfig/iptables')
        if os_version >= 7:
            run('systemctl restart firewalld')
        else:
            run('service iptables restart')

        # Restart the libvirt daemon
        if os_version >= 7:
            run('systemctl reload libvirtd')
        else:
            run('service libvirtd reload')

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
        if run(command, warn_only=True).return_code != 0:
            time.sleep(5)
            run(command)

    # It is recommended that a time synchronizer such as ntpd is installed and
    # enabled on Satellite Server. To enable ntpd and have it persist at
    # bootup:
    run('yum install -y ntp', warn_only=True)

    # The command varies depending on what version of RHEL you have.
    os_version = distro_info()[1]

    if os_version >= 7:
        run('systemctl enable ntpd', warn_only=True)
        run('systemctl start ntpd', warn_only=True)
    else:
        run('service ntpd start', warn_only=True)
        run('chkconfig ntpd on', warn_only=True)

    # Port 443 for HTTPS (secure WWW) must be open for incoming connections.
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT')

    # Port 5671 must be open for SSL communication with managed systems.
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 5671 -j ACCEPT')

    # Port 80 for HTTP (WWW) must be open to download the bootstrap files.
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT')

    # Port 8140 must be open for incoming Puppet connections with the managed
    # systems.
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 8140 -j ACCEPT')

    # Port 9090 must be open for Foreman Smart Proxy connections with the
    # managed systems.
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 9090 -j ACCEPT')

    # Port 22 must be open for connections via ssh
    run('iptables -I INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT')

    # To make the changes persistent across reboots when using the command line
    # use this command:
    run('iptables-save > /etc/sysconfig/iptables')


def manage_repos(os_version=None, cdn=False):
    """Enables only required RHEL repos for Satellite 6."""

    if os_version is None:
        print('Please provide the OS version.')
        sys.exit(1)

    if isinstance(cdn, str):
        cdn = (cdn.lower() == 'true')

    # Clean up system if Beaker-based
    result = run('which yum-config-manager', warn_only=True)
    if result.return_code == 0:
        run('yum-config-manager --disable "beaker*"')
    else:
        run('mv /etc/yum.repos.d/beaker-* ~/', warn_only=True)
    run('rm -rf /var/cache/yum*')

    # Disable yum plugin for sub-man
    run('sed -i -e "s/^enabled.*/enabled=0/" '
        '/etc/yum/pluginconf.d/subscription-manager.conf')
    # And disable all repos for now
    run('subscription-manager repos --disable "*"')

    # If installing from CDN, use the real product
    if cdn is True:
        run(
            'subscription-manager repos --enable '
            '"rhel-{0}-server-satellite-6.0-rpms"'.format(os_version)
        )
    # Enable 'base' OS rpms
    run('subscription-manager repos --enable "rhel-{0}-server-rpms"'.format(
        os_version))
    # Enable SCL
    run('subscription-manager repos --enable "rhel-server-rhscl-{0}-rpms"'
        ''.format(os_version))
    run('yum repolist')

    # Update packages
    update_packages(warn_only=True)


def upstream_install(admin_password=None, org_name=None, loc_name=None):
    """Task to install Foreman nightly using katello-deploy script"""
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    if org_name is None:
        org_name = os.environ.get('ORGANIZATION_NAME', 'Default_Organization')
    if loc_name is None:
        loc_name = os.environ.get('LOCATION_NAME', 'Default_Location')

    os_version = distro_info()[1]

    manage_repos(os_version)

    # Install required packages for the installation
    run('yum install -y git ruby')

    run('if [ -d katello-deploy ]; then rm -rf katello-deploy; fi')
    run('git clone https://github.com/Katello/katello-deploy.git')

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('yum repolist')
    run('cd katello-deploy && ./setup.rb --skip-installer '
        '--os rhel{os_version}'.format(os_version=os_version))
    run('yum repolist')
    run('katello-installer -v -d '
        '--foreman-admin-password="{0}" '
        '--foreman-initial-organization="{1}" '
        '--foreman-initial-location="{2}"'
        ''.format(admin_password, org_name, loc_name))
    run('yum repolist')

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def downstream_install(admin_password=None):
    """Task to install Satellite 6

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    BASE_URL
        URL for the compose repository.

    """
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    os_version = distro_info()[1]

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

    manage_repos(os_version)

    # Install required packages for the installation
    run('yum install -y katello libvirt')

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def cdn_install():
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

    os_version = distro_info()[1]

    # Enable some repos
    manage_repos(os_version, True)

    # Install required packages for the installation
    run('yum install -y katello libvirt')

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def iso_install(iso_url=None, check_sigs=False):
    """Installs Satellite 6 from an ISO image."""

    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    os_version = distro_info()[1]

    # Check that we have a URL
    if iso_url is None:
        print('Please provide a valid URL for the ISO image.')
        sys.exit(1)
    # Wether we should check for package signatures
    if isinstance(check_sigs, str):
        check_sigs = (check_sigs.lower() == 'true')

    # Enable some repos
    manage_repos(os_version)

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

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def product_install(distribution, create_vm=False, certificate_url=None):
    """Task which install every product distribution.

    Product distributions are cdn, downstream, iso or upstream.

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
    distribution = distribution.lower()

    install_tasks = {
        'cdn': cdn_install,
        'downstream': downstream_install,
        'iso': iso_install,
        'upstream': upstream_install,
    }
    distributions = install_tasks.keys()
    if distribution not in distributions:
        print('distribution "{0}" should be one of {1}'.format(
            distribution, ', '.join(distributions)))
        sys.exit(1)

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

    execute(install_tasks[distribution], host=host)

    if distribution in ('cdn', 'downstream', 'iso'):
        execute(setup_default_capsule, host=host)

    execute(setup_default_docker, host=host)

    # execute returns a dict, the result is the first value
    info = execute(distro_info, host=host).values()[0]
    if info[1] == 7:
        execute(setup_abrt, host=host)
    else:
        print('WARNING: ABRT was not set up')

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

        for sum_file in ('MD5SUM', 'SHA1SUM', 'SHA256SUM'):
            result = run(
                'wget {0} -O - -q'.format(urljoin(iso_url, sum_file)),
                quiet=True,
                warn_only=True
            )
            if result.return_code == 0:
                iso_filename = result.split('*')[1].strip()
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


def distro_info():
    """Task which figures out the distro information based on the
    /etc/redhat-release file

    A `(distro, major_version)` tuple is returned if called as a function. For
    RHEL X.Y.Z it will return ('rhel', X). For Fedora X it will return
    ('fedora', X). Be aware that the major_version is an integer.

    """
    # Create/manage host cache
    cache = env.get('distro_info_cache')
    host = env['host']
    if cache is None:
        cache = env['distro_info_cache'] = {}

    if host not in cache:
        # Grab the information and store on cache
        release_info = run('cat /etc/redhat-release', quiet=True)
        if release_info.return_code != 0:
            print('Failed to read /etc/redhat-release file')
            sys.exit(1)

        # Discover the distro
        if release_info.startswith('Red Hat Enterprise Linux'):
            distro = 'rhel'
        elif release_info.startswith('Fedora'):
            distro = 'fedora'
        else:
            distro = None

        # Discover the version
        match = search(r' ([0-9.]+) ', release_info)
        if match is not None:
            parts = match.group(1).split('.')
            # extract the major version
            major_version = int(parts[0])
            # extract the minor version
            if len(parts) > 1:
                minor_version = int(parts[1])
            else:
                minor_version = None
        else:
            major_version = minor_version = None

        if distro is None or major_version is None:
            print('Was not possible to fetch distro information')
            sys.exit(1)

        cache[host] = distro, major_version, minor_version

    distro, major_version, minor_version = cache[host]
    print('{0} {1} {2}'.format(distro, major_version, minor_version))
    return distro, major_version, minor_version


def performance_tuning(running_on_vm=True):
    """Task which tunes up the Satellite 6 performance

    Set running_on_vm to False if improving performance on a bare metal machine

    """
    # Command-line arguments are passed in as strings.
    if isinstance(running_on_vm, str):
        running_on_vm = (running_on_vm.lower() == 'true')

    distro_version = distro_info()[1]
    if distro_version <= 6:
        service_management_cmd = 'service {0} {1}'
    else:
        service_management_cmd = 'systemctl {1} {0}'

    # httpd configuration
    run('sed -i -e "s/^KeepAlive.*/KeepAlive On/" '
        '/etc/httpd/conf/httpd.conf')
    run(service_management_cmd.format('httpd', 'restart'))

    # tuned setup
    run('yum install -y tuned', warn_only=True)
    if distro_version <= 6:
        run('chkconfig tuned on')
    else:
        run('systemctl enable tuned')
    run(service_management_cmd.format('tuned', 'start'))
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
    run('yum erase -y $(rpm -qa |grep katello-ca-consumer)',
        warn_only=True, quiet=True)
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
    update_packages(
        'subscription-manager', 'yum-utils', warn_only=True, quiet=True)
    run('yum install -y yum-plugin-security yum-security',
        warn_only=True, quiet=True)
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
    run('service httpd start', warn_only=True)
    print('Stopping "httpd" service and remove "Web Server" group.')
    run('service httpd stop', warn_only=True)
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

    erratum = run('yum list-sec', warn_only=True, quiet=True)

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

    # The command varies depending on what version of RHEL you have.
    if distro_info()[1] >= 7:
        run('systemctl status goferd')
    else:
        run('service goferd status')


def remove_katello_agent():
    """Removes the 'katello-agent' package."""
    # Check that the package is installed
    run('rpm -q katello-agent')
    # Remove it
    run('rpm -e katello-agent')
    # Now, check that the package is indeed gone...
    run('rpm -q katello-agent', warn_only=True)
    # ...and that 'goerd' is not running.

    # The command varies depending on what version of RHEL you have.
    if distro_info()[1] >= 7:
        run('systemctl status goferd', warn_only=True)
    else:
        run('service goferd status', warn_only=True)


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
    if result.return_code == 0:
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
    if distro_info()[1] >= 7:
        run('systemctl start {0}d'.format(package1))
    else:
        run('service {0}d start'.format(package1))

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
    """Run the errata to upgrade packages

    The following environment variables affect this command

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
    run('{0}-setup-channel-cache'.format(package2))
    run('tps-make-lists {0}'.format(errata_number))
    run('{0}-cd -c {1} && {0}-upgrade'
        .format(package2, errata_number))

    # After this you can see the upgraded packages
    # Run `<package2>-downgrade` if you want to revert to the old packages


def update_packages(*args, **kwargs):
    """Updates all system packages or only ones specified by `args`

    Use this if you want to simply update all packages or some on system.
    Possibly useful for when doing upgrades, etc.

    """
    if len(args) > 0:
        arguments = ' '.join(args)
    else:
        arguments = ''

    run(
        'yum update -y {0}'.format(arguments),
        quiet=kwargs.get('quiet', False),
        warn_only=kwargs.get('warn_only', False),
    )
