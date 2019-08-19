"""A set of tasks for automating interactions with Satellite servers.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
from __future__ import print_function
import base64
import os
import random
import socket
import sys
import time
from datetime import date
from io import StringIO
from re import search

from automation_tools.bz import bz_bug_is_open
from automation_tools.repository import (
    create_custom_repos, disable_repos, disable_beaker_repos, enable_repos, enable_satellite_repos,
)
from automation_tools.utils import (
    distro_info, run_command, update_packages
)
from fabric.api import cd, env, execute, get, hide, local, put, run, settings, sudo

from six.moves.urllib.parse import urljoin
from six.moves.urllib.parse import urlsplit

LIBVIRT_IMAGES_DIR = '/var/lib/libvirt/images'


def unsubscribe():
    """Unregisters a machine from Red Hat"""
    run('subscription-manager unregister', warn_only=True)
    run('subscription-manager clean')


def subscribe(autosubscribe=False, stage=False):
    """Registers and subscribes machine to Red Hat.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.

    :param bool stage: Subscribe to stage

    """

    # Registration and subscription is only meaningful for Red Hat Enterprise
    # Linux systems.
    distro, major_version, _ = distro_info()
    if distro.lower() != 'rhel':
        return

    for env_var in ('RHN_USERNAME', 'RHN_PASSWORD'):
        if env_var not in os.environ:
            print('The {0} environment variable must be set.'.format(env_var))
            sys.exit(1)

    # Clean and reset subscription manager to CDN defaults
    clean_rhsm()

    # Point subscription manager to stage if requested
    if stage:
        update_rhsm_stage()

    # Register the system
    with hide('running'):
        run(
            'subscription-manager register --force --user={0} --password={1} {2} {3}'.format(
                os.environ['RHN_USERNAME'],
                os.environ['RHN_PASSWORD'],
                # set release to "6Server", "7Server" or "8" accordingly
                '--release="{0}{1}"'.format(major_version, 'Server' if major_version < 8 else ''),
                '--auto-attach' if autosubscribe else ''
            )
        )

    # Subscribe the system if a pool ID was provided
    # Multiple pool IDs can be provided as space seprated list
    rhn_poolid = os.environ.get('RHN_POOLID')
    if rhn_poolid:
        has_pool_msg = (
            'This unit has already had the subscription matching pool ID'
        )
        attach_cmd = 'subscription-manager attach {0}'.format(
            ' '.join(['--pool={0}'.format(id) for id in rhn_poolid.split()])
        )

        for _ in range(10):
            result = run(attach_cmd, warn_only=True)
            if result.succeeded or has_pool_msg in result:
                return
            time.sleep(5)
        print('Unable to attach system to pool. Aborting.')
        sys.exit(1)


def subscribe_dogfood(clean_beaker=True):
    """Registers and subscribes machine to dogfood Satellite.

    The following environment variables affect this command:

    DOGFOOD_URL
        URL for the Candlepin Cert RPM.
    DOGFOOD_ORG
        ORG for the sat63 to subscribe to.
    DOGFOOD_ACTIVATIONKEY
        AK for the sat63 to subscribe to.

    """

    # DOGFOOD Url
    dogfood_url = os.getenv('DOGFOOD_URL')
    if not dogfood_url:
        print('You need to provide the Dogfood Url.')
        sys.exit(1)
    # Org
    org = os.getenv('DOGFOOD_ORG')
    if not org:
        print('You need to provide the Organization to subscribe.')
        sys.exit(1)
    # Activation Key
    act_key = os.getenv('DOGFOOD_ACTIVATIONKEY')
    if not act_key:
        print('You need to provide an activationkey.')
        sys.exit(1)

    # If this is a Beaker box, 'disable' Beaker repos
    if clean_beaker is True:
        disable_beaker_repos(silent=True)

    # Clean up and install with basic packages.
    clean_rhsm()

    # Install the cert file
    run('yum -y localinstall {0}/pub/katello-ca-consumer-latest.noarch.rpm'
        .format(dogfood_url), warn_only=True)

    # Register and subscribe
    print('Register/Subscribe using Subscription-manager.')
    cmd = (
        'subscription-manager register --force --org="{0}" '
        '--activationkey="{1}"'.format(org, act_key)
    )
    run(cmd)

    # Refresh subscriptions and clean up YUM
    print('Refreshing Subscription-manager.')
    run('subscription-manager refresh')
    print('Performing yum clean up.')
    run('yum clean all', quiet=True)


def setup_ddns(entry_domain, host_ip):
    """Task to setup DDNS client

    The following environment variables affect this command:

    * `DDNS_HASH`
    * `DDNS_PACKAGE_URL`
    * `INTERNAL_CERT_URL`

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

    os_version = distro_info()[1]

    target, domain = entry_domain.split('.', 1)

    if os_version >= 7:
        internal_cert_url = os.environ.get('internal_cert_url')
        if internal_cert_url is None:
            print('The internal_cert_url environment variable should be defined')
            sys.exit(1)

        run('yum localinstall -y {0}'.format(internal_cert_url))

    run('yum localinstall -y {0}'.format(ddns_package_url))

    if os_version >= 7:
        run('echo "{0} {1} {2}" >> /etc/redhat-internal-ddns/hosts'.format(
            target, domain, ddns_hash))
        fix_hostname(entry_domain, host_ip)
        run('redhat-internal-ddns-client.sh enable')
        run('redhat-internal-ddns-client.sh update')
    else:
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


def setup_avahi_discovery():
    """Task to setup avahi discovery used to discover VMs deployed to a VLAN
       by 'ping vm.local' run at Satellite
    """
    os_version = distro_info()[1]
    if run('rpm -q nss-mdns', warn_only=True).failed:
        if os_version == 8:  # temporary fix until EPEL8 goes out
            run('yum -y install https://dl.fedoraproject.org/pub/epel/7/x86_64/Packages'
                '/n/nss-mdns-0.14.1-1.el7.x86_64.rpm')
        else:
            epel_present = run('rpm -q epel-release', warn_only=True).return_code == 0
            if not epel_present:
                run('yum -y install https://dl.fedoraproject.org/pub/epel/'
                    'epel-release-latest-{0}.noarch.rpm'.format(os_version))
            run('yum -y install nss-mdns')  # also pulls in avahi
            if not epel_present:  # we installed epel, so removing aftwerwards
                run('rpm -e epel-release')

    if os_version >= 7:
        run('firewall-cmd --add-service mdns --permanent')
        run('firewall-cmd --reload')
    else:
        run('iptables -I INPUT -d 224.0.0.251/32 -p udp -m udp --dport 5353'
            ' -m conntrack --ctstate NEW -j ACCEPT')
    run('service avahi-daemon restart')


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
        # enable the service as it is disabled by default
        run('systemctl enable docker.service')
        # Disable 'extras' repo after installing Docker
        disable_repos('rhel-{0}-server-extras-rpms'.format(os_version))
    else:
        run('yum install -y docker-io', warn_only=True)
        # Uninstall EPEL package rather than delete just the epel.repo file.
        run('yum remove -y epel-release.noarch')

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

    # enable the service as it is disabled by default on RHEL7
    manage_daemon('enable', 'docker', pty=(os_version >= 7))
    manage_daemon('restart', 'docker', pty=(os_version >= 7),
                  warn_only=bz_bug_is_open('1414821'))


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
    if '.' not in hostname:
        print('Please make sure the hostname is configured with a FQDN')
        sys.exit(1)

    domain = hostname.split('.', 1)[1]
    if len(domain) == 0:
        print('Was not possible to fetch domain information')
        sys.exit(1)

    if interface is None:
        if len(interface) == 0:
            print('Was not possible to fetch interface information')
            sys.exit(1)

    installer_options = {
        'foreman-proxy-dns': 'true',
        'foreman-proxy-dns-forwarders': forwarders,
        'foreman-proxy-dns-interface': interface,
        'foreman-proxy-dns-zone': domain,
        'foreman-proxy-dhcp': 'true',
        'foreman-proxy-dhcp-interface': interface,
        'foreman-proxy-tftp': 'true',
        'foreman-proxy-tftp-servername': hostname,
        'foreman-proxy-register-in-foreman': 'true',
    }

    installer_options[
        'foreman-proxy-dhcp-range'
    ] = os.environ.get('DHCP_RANGE', '192.168.100.10 192.168.100.254')

    gateway = os.environ.get('GATEWAY', '192.168.100.1')
    installer_options['foreman-proxy-dhcp-gateway'] = gateway
    zone = gateway.rpartition('.')[0]
    reversed_zone = '.'.join(reversed(zone.split('.')))
    dns_reverse_zone = '{0}.in-addr.arpa'.format(reversed_zone)
    installer_options['foreman-proxy-dns-reverse'] = dns_reverse_zone

    if run_katello_installer:
        katello_installer(**installer_options)
    else:
        return installer_options


def setup_external_capsule():
    """Task to setup an external Capsule for Satellite."""
    interface = os.environ.get('INTERFACE', 'virbr0')
    gateway = os.environ.get('GATEWAY', '192.168.200.1')
    if 'virbr' in interface:
        setup_default_libvirt(ip_address=gateway)
    install_options = setup_default_capsule(
        interface=interface,
        run_katello_installer=False)
    katello_installer(scenario="capsule", **install_options)


def setup_default_libvirt(bridge=None, ip_address="192.168.100.1"):
    """Task to setup a the default capsule for Satellite

    :param str interface: Network interface name to be used
    """
    run('yum install -y libvirt libvirt-daemon-kvm virt-install qemu-kvm')
    run('lsmod | grep kvm_', warn_only=True)
    run('sed -i \'s/^#*\\s*LIBVIRTD_ARGS=.*/LIBVIRTD_ARGS=--listen/\' /etc/sysconfig/libvirtd')
    run('sed -i \'s/^#*\\s*listen_tls\\s*=.*/listen_tls = 0/\' /etc/libvirt/libvirtd.conf')
    run('sed -i \'s/^#*\\s*listen_tcp\\s*=.*/listen_tcp = 1/\' /etc/libvirt/libvirtd.conf')
    run('sed -i \'s/^#*\\s*auth_tcp\\s*=.*/auth_tcp = "none"/\' /etc/libvirt/libvirtd.conf')
    manage_daemon('enable', 'libvirtd')
    manage_daemon('restart', 'libvirtd')

    if 'default' in run('virsh net-list'):
        run('virsh net-destroy default')
        run('virsh net-undefine default')

    # Setup foreman libvirt network
    if 'foreman' not in run('virsh net-list --all'):
        run('virsh net-define <(echo "\n'
            '<network>\n'
            '  <name>foreman</name>\n'
            '  <forward mode=\'nat\'>\n'
            '    <nat>\n'
            '      <port start=\'1024\' end=\'65535\'/>\n'
            '    </nat>\n'
            '  </forward>\n' +
            ('  <bridge name=\'{}\' stp=\'on\' delay=\'0\'/>\n'.format(bridge)
                if bridge else '') +
            ('  <ip address=\'{0}\' netmask=\'255.255.255.0\'>\n'
                .format(ip_address)) +
            '  </ip>\n'
            '</network>")')
        run('virsh net-start foreman')
    run('virsh net-autostart foreman')

    os_version = distro_info()[1]
    if os_version >= 7:
        manage_daemon('start', 'firewalld')
        run('firewall-cmd --add-service vnc-server --permanent')
        run('firewall-cmd --service=vnc-server --add-port=5901-5999/tcp '
            '--permanent')
        run('firewall-cmd --reload')
    else:
        run('iptables -I INPUT -m state --state NEW -p tcp --dport 5901:5999 '
            '-j ACCEPT')
        # To make the changes persistent across reboots
        manage_daemon('save', 'iptables')

    # Fetch virtual bridge information
    interface = run('virsh net-info foreman | awk \'/Bridge:/{printf$2}\'')
    return interface


def setup_default_subnet(sat_version):
    """Postinstall task to setup default subnet within Satellite

    Expects the following environment variables:

    SUBNET
        The network address that Internal Capsule resides in
    NETMASK
        The netmask of the subnet
    GATEWAY
        The gateway in the subnet
    DHCP_RANGE
        The range in the subnet operated by DHCP Capsule

    :param str sat_version: contains Satellite version (e.g. 6.3, 6.4)
    """
    dhcp_range = os.environ.get(
        'DHCP_RANGE', '192.168.100.10 192.168.100.254').split()
    options = {
        'password': os.environ.get('ADMIN_PASSWORD', 'changeme'),
        'network':  os.environ.get('SUBNET', '192.168.100.0'),
        'mask':     os.environ.get('NETMASK', '255.255.255.0'),
        'gateway':  os.environ.get('GATEWAY', '192.168.100.1'),
        'from':     dhcp_range[0], 'to': dhcp_range[1],
    }
    command = (
        'hammer -u admin -p {password} subnet create --name "Default Subnet" '
        '--network {network} --mask {mask} '
        '--gateway {gateway} --dns-primary {gateway} '
        '--ipam DHCP --from {from} --to {to} '
        '--dhcp-id 1 --dns-id 1 --tftp-id 1 --discovery-id 1'
    ).format(**options)
    # create or update if failed
    if run(command, warn_only=True).failed:
        run(command.replace(' create ', ' update ', 1))


def setup_bfa_prevention(bfa_limit=0):
    """Postinstall task to set the `failed_login_attempts_limit` global setting
    to control brute-force-attack prevention.

    Expects the following environment variables:

    :param int bfa_limit: number of failed login attempts in 5 minute to trigger BFA prevention
        0 (default) disables BFA prevention

    """

    command = (
        'hammer -u admin -p {0} settings set --name "failed_login_attempts_limit" --value {1}'
    ).format(os.environ.get('ADMIN_PASSWORD', 'changeme'), bfa_limit)
    run(command, warn_only=True)


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


def setup_firewall(definitions=None, flush=True):
    """Setup firewall rules based on the ``definitions``.

    :param definitions: A dict containing the definitions for the
        firewall rules, for example::

            definitions = {
                'tcp': (
                    42,
                    9090,
                ),
                'udp': (
                    4242,
                    4422,
                ),
            }
    :param flush: If ``True`` will clean up all rules before adding the rules
        specified by ``definitions``.
    """
    if definitions is None:
        return
    os_version = distro_info()[1]
    if os_version < 7:
        exists_command = r'iptables -nL INPUT | grep -E "^ACCEPT\s+{0}.*{1}"'
        command = (
            'iptables -I INPUT -m state --state NEW -p {0} --dport {1} '
            '-j ACCEPT'
        )
        if flush:
            run('iptables --flush')
    else:
        if run('rpm -q firewalld', quiet=True).failed:
            run('yum install -y firewalld')
        if run('systemctl --no-pager status firewalld', quiet=True).failed:
            run('systemctl enable firewalld')
            run('systemctl start firewalld')
        exists_command = 'firewall-cmd --permanent --query-port="{1}/{0}"'
        command = ['firewall-cmd --permanent']
        if flush:
            ports = run('firewall-cmd --permanent --list-ports').split()
            flush_cmd = 'firewall-cmd --permanent {0}'.format(
                ' '.join(['--remove-port="{0}"'.format(p) for p in ports])
            )
            if ports:
                run(flush_cmd)

    for protocol in definitions:
        for port in definitions[protocol]:
            rule_exists = False if flush else run(
                exists_command.format(protocol, port), quiet=True
            ).succeeded
            if not rule_exists:
                if os_version < 7:
                    run(command.format(protocol, port))
                else:
                    # rhel7: only build command
                    command.append(
                        '--add-port="{1}/{0}"'.format(protocol, port)
                    )
    if os_version >= 7 and len(command) > 1:
        # rhel7: run built command since it was appended
        run(' '.join(command))

    if os_version < 7:
        # To make the changes persistent across reboots
        manage_daemon('save', 'iptables')
        manage_daemon('enable', 'iptables')
    else:
        # To activate persistent settings as the current ones
        run('firewall-cmd --reload')


def setup_satellite_firewall():
    """Setup firewall rules that Satellite 6 needs to work properly."""
    setup_firewall({
        'tcp': (
            # Port 80 for HTTP (WWW) must be open to download the bootstrap
            # files.
            80,
            # Port 443 for HTTPS (secure WWW) must be open for incoming
            # connections.
            443,
            # Ports 5646 and 5647 for qpidd
            5646,
            5647,
            # Port 5671 must be open for SSL communication with managed
            # systems.
            5671,
            # Port 8000 for foreman-proxy service
            8000,
            # Port 8140 must be open for incoming Puppet connections with the
            # managed systems.
            8140,
            # Port 8443 for Katello access the Isolated Capsule
            8443,
            # Port 9090 must be open for Foreman Smart Proxy connections with
            # the managed systems.
            9090,
            # Automation controls machine via ssh
            22,
            # Local docker listens on 2375/tcp (done by setup_default_docker)
            2375,
            # Port 5000 must be open for Docker registry communication.
            5000,
            # Local libvirt listens on 16509/tcp (done by katellovirt module)
            16509,
        ),
        'udp': (
            # Port 53 must be open for DNS Capsule Feature.
            53,
            # Port 69 must be open for TFTP Capsule Feature.
            69,
        ),
    })


def setup_capsule_firewall():
    """Setup firewall rules that a Satellite 6 Capsule needs to work
    properly.
    """
    setup_firewall({
        'tcp': (
            # Connections to the proxy in the Capsule and sending
            # generated SCAP reports to the proxy in the Capsule for
            # spooling
            9090,
            # Queries to the DNS service
            53,
            # Anaconda, yum, and for obtaining Katello certificate updates
            80,
            # Anaconda, yum, Telemetry Services, and Puppet
            443,
            # The Katello agent to communicate with the Capsule's Qpid dispatch
            # router
            5647,
            # Anaconda to download kickstart templates to hosts, and for
            # downloading iPXE firmware
            8000,
            # Puppet agent to Puppet master connections
            8140,
            # Subscription Management Services connection to the reverse proxy
            # for the certificate-based API
            8443,
        ),
        'udp': (
            # Queries to the DNS service
            53,
            # For Client provisioning from the Capsule
            67,
            68,
            # Downloading PXE boot image files
            69,
        ),
    })


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


def setup_python_code_coverage():
    """Task to setup python code coverage on Satellite 6."""
    os_version = distro_info()[1]
    # This has to be inside the function so that it runs actually on Sat6.
    if os_version == 6:
        return

    run('mkdir -p /etc/coverage')
    coveragerc_file = StringIO()
    coveragerc_file.write(u'[run]\n')
    coveragerc_file.write(u'source=\n')
    coveragerc_file.write(u'    pulp\n')
    coveragerc_file.write(u'    pulp_deb=\n')
    coveragerc_file.write(u'    pulp_docker\n')
    coveragerc_file.write(u'    pulp_openstack\n')
    coveragerc_file.write(u'    pulp_ostree\n')
    coveragerc_file.write(u'    pulp_puppet\n')
    coveragerc_file.write(u'    pulp_python\n')
    coveragerc_file.write(u'    pulp_rpm\n')
    coveragerc_file.write(u'\n')
    coveragerc_file.write(u'data_file=/etc/coverage/.coverage\n')
    coveragerc_file.write(u'\n')
    coveragerc_file.write(u'parallel=true\n')
    coveragerc_file.write(u'\n')
    coveragerc_file.write(u'concurrency=\n')
    coveragerc_file.write(u'    multiprocessing\n')
    coveragerc_file.write(u'    thread\n')
    coveragerc_file.write(u'\n')
    coveragerc_file.write(u'[xml]\n')
    coveragerc_file.write(u'output=/etc/coverage/coverage.xml\n')
    put(local_path=coveragerc_file,
        remote_path='/etc/coverage/.coveragerc')
    coveragerc_file.close()

    sitecustomize_file = StringIO()
    sitecustomize_file.write(u'import os\n')
    sitecustomize_file.write(u'os.environ[\'COVERAGE_PROCESS_START\']')
    sitecustomize_file.write(u' = \'/etc/coverage/.coveragerc\'\n')
    sitecustomize_file.write(u'# Import coverage after editing environment\n')
    sitecustomize_file.write(u'import coverage\n')
    sitecustomize_file.write(u'coverage.process_startup()\n')
    if os_version == 7:
        put(local_path=sitecustomize_file,
            remote_path='/usr/lib/python2.7/site-packages/sitecustomize.py')
    sitecustomize_file.close()

    # Install EPEL packages for the installation
    epel_present = run('rpm -q epel-release', warn_only=True).return_code == 0
    if not epel_present:
        run('yum -y install https://dl.fedoraproject.org/pub/epel/'
            'epel-release-latest-{0}.noarch.rpm'.format(os_version))
    run('yum -y install python-pip')
    run('pip install -U coverage')
    # Uninstall EPEL package only if we have installed it (leave for upstream)
    if not epel_present:
        run('rpm -e epel-release')
    run('chcon -R -u system_u -t httpd_sys_rw_content_t /etc/coverage')
    run('chmod -R 777 /etc/coverage ; chown -R apache.apache /etc/coverage')


def setup_ruby_code_coverage():
    """Task to setup ruby code coverage on Satellite 6."""

    os_version = distro_info()[1]
    # This has to be inside the function so that it runs actually on Sat6.
    if os_version == 6:
        return

    # Install ruby-devel package from the rhel optional installation
    # Enable required repository
    run('subscription-manager repos --enable rhel-{0}-server-optional-rpms'
        .format(os_version))
    run('yum -y install ruby-devel')
    # Install gcc package so that we can install the ruby gems.
    run('yum -y install gcc')
    # Installing simplecov and simplecov-rcov rubygems for system folder.
    run('gem install simplecov ; gem install simplecov-rcov')
    # Installing simplecov and simplecov-rcov rubygems for scl - tfm.
    run('scl enable tfm \'gem install simplecov\'')
    # Installing simplecov and simplecov-rcov rubygems for scl - tfm.
    run('scl enable tfm \'gem install simplecov-rcov\'')
    # Installing for dependencies.
    run('scl enable tfm \'gem install docile\'')
    run('scl enable tfm \'gem install json\'', quiet=True)

    run('echo "export RUBY_SYS_COVERAGE_CONFIG=/etc/coverage/ruby/sys/'
        'config_sys.yml" >> ~/.bashrc')
    run('echo "export RUBY_TFM_COVERAGE_CONFIG=/etc/coverage/ruby/tfm/'
        'config_tfm.yml" >> ~/.bashrc')
    run('for i in `find / -name simplecov-html.rb`; do sed -i -e '
        '"s/puts output_message(result)/# puts output_message(result)/"'
        ' $i; done')


# This function sets up the ruby code coverage around satellite-installer and
# the proxy. This mostly deals with system rubygems.
def setup_rubysys_code_coverage():
    """Task to setup ruby code coverage for system file on Satellite 6.

    The following environment variables affect this task:

        * `RUBY_SYS_COVERAGE_URL`
    """

    run('mkdir -p /etc/coverage/ruby/sys/')
    coverageruby_file = StringIO()
    coverageruby_file.write(u'---\n')
    coverageruby_file.write(u'project_folder_name :')
    coverageruby_file.write(u' \'/usr/share/gems/gems/\'\n')
    coverageruby_file.write(u'report_directory :')
    coverageruby_file.write(u' \'/etc/coverage/ruby/sys/reports/\'\n')
    coverageruby_file.write(u'analysis_name : \'ruby_subprocess_coverage\'\n')
    coverageruby_file.write(u'...\n')
    put(local_path=coverageruby_file,
        remote_path='/etc/coverage/ruby/sys/config_sys.yml')
    coverageruby_file.close()

    coverage_sys_url = os.getenv('RUBY_SYS_COVERAGE_URL')
    coverage_sys_file = '/root/coverage_sys.rb'
    coverage_sys_rubygems = '/usr/share/rubygems/rubygems.rb'
    if not coverage_sys_url:
        print('You need to provide the SYS Coverage Url.')
        sys.exit(1)

    run('wget -O {0} {1}'.format(coverage_sys_file, coverage_sys_url))
    run('cat {0} >> {1}'.format(coverage_sys_file, coverage_sys_rubygems))


# This function sets up the ruby code coverage around foreman and katello(tfm).
# This mostly deals with tfm rubygems from RedHat software collections (scl).
def setup_rubytfm_code_coverage():
    """Task to setup ruby code coverage for tfm files on Satellite 6.

    The following environment variables affect this task:

        * `RUBY_TFM_COVERAGE_URL`
    """

    run('mkdir -p /etc/coverage/ruby/tfm/')
    coverageruby_file = StringIO()
    coverageruby_file.write(u'---\n')
    coverageruby_file.write(u'project_folder_name :')
    coverageruby_file.write(u' \'/opt/theforeman/tfm')
    coverageruby_file.write(u'/root/usr/share/gems/gems/\'\n')
    coverageruby_file.write(u'report_directory :')
    coverageruby_file.write(u' \'/etc/coverage/ruby/tfm/reports/\'\n')
    coverageruby_file.write(u'analysis_name : \'ruby_subprocess_coverage\'\n')
    coverageruby_file.write(u'...\n')
    put(local_path=coverageruby_file,
        remote_path='/etc/coverage/ruby/tfm/config_tfm.yml')
    coverageruby_file.close()

    coverage_tfm_url = os.getenv('RUBY_TFM_COVERAGE_URL')
    coverage_tfm_file = '/root/coverage_tfm.rb'
    coverage_tfm_rubygems = (
                          '/opt/rh/rh-ruby23/root'
                          '/usr/share/rubygems/rubygems.rb')
    if not coverage_tfm_url:
        print('You need to provide the TFM Coverage Url.')
        sys.exit(1)

    run('wget -O {0} {1}'.format(coverage_tfm_file, coverage_tfm_url))
    run('cat {0} >> {1}'.format(coverage_tfm_file, coverage_tfm_rubygems))


def configure_sonarqube():
    """Task to configure SonarQube.

    The following environment variables affect this task:

        * `HTTP_SERVER_HOSTNAME`
        * `SONAR_SERVER_URL`
        * `SATELLITE_VERSION`
        * `BUILD_LABEL`
        * `SONAR_LOGIN`
        * `SONAR_PASSWORD`
    """
    http_server = os.environ.get('HTTP_SERVER_HOSTNAME')
    sonar_server = os.environ.get('SONAR_SERVER_URL')
    satellite_version = os.environ.get('SATELLITE_VERSION')
    build_label = os.environ.get('BUILD_LABEL')
    sonar_login = os.environ.get('SONAR_LOGIN')
    sonar_password = os.environ.get('SONAR_PASSWORD')
    # Sonar Scanner requires Java1.8 to be able to upload content to SonarQube
    run('yum -y install java-1.8.0-openjdk')

    # Download and Install Sonar-Scanner 2.6
    run('wget {0}/pub/sonar-scanner-2.6-SNAPSHOT.zip'.format(http_server))
    run('unzip sonar-scanner-2.6-SNAPSHOT.zip')

    # Run the Sonar-Scanner to actually upload the results to SonarQube.
    run('sonar-scanner-2.6-SNAPSHOT/bin/sonar-scanner -X -e '
        '-Dsonar.host.url={0} -Dsonar.language=py -Dsonar.ws.timeout=180 '
        '-Dsonar.projectVersion={1} '
        '"-Dsonar.projectName=Satellite{2} Pulp Python Analysis" '
        '"-Dsonar.python.coverage.reportPath=/etc/coverage/coverage.xml" '
        '"-Dsonar.projectKey=Satellite{2}_pulp_python_full_analysis" '
        '-Dsonar.projectBaseDir=/usr/lib/python2.7/site-packages/ '
        '-Dsonar.sources=pulp,pulp_docker,pulp_katello,pulp_ostree,pulp_puppet'
        ',pulp_rpm "-Dsonar.exclusions=pulp_docker/plugins/distributors/'
        'distributor_export.py,pulp_rpm/extensions/*.py" '
        '"-Dsonar.login={3}" "-Dsonar.password={4}"'
        .format(
            sonar_server, build_label, satellite_version,
            sonar_login, sonar_password))

    if os.environ.get('RUBY_CODE_COVERAGE') == 'true':
        run('sonar-scanner-2.6-SNAPSHOT/bin/sonar-scanner -X -e '
            '-Dsonar.host.url={0} -Dsonar.language=ruby '
            '-Dsonar.ws.timeout=180 -Dsonar.projectVersion={1} '
            '"-Dsonar.projectName=Satellite{2} TFM Ruby Analysis" '
            '"-Dsonar.simplecovrcov.reportPath=/etc/coverage'
            '/ruby/tfm/reports/results.json" '
            '"-Dsonar.projectKey=Satellite{2}_tfm_ruby_full_analysis" '
            '-Dsonar.projectBaseDir=/opt/theforeman/tfm/root'
            '/usr/share/gems/gems/ '
            '-Dsonar.sources=/opt/theforeman/tfm/root/usr/share/gems/gems/ '
            '"-Dsonar.login={3}" "-Dsonar.password={4}"'
            .format(
                sonar_server, build_label, satellite_version,
                sonar_login, sonar_password))


def install_ansible_scap_client():
    """Task to install ansiblerole-foreman_scap_client."""
    # Install required packages for the installation
    run('yum -y install ansiblerole-foreman_scap_client')


def oscap_content():
    """Task to populate Default oscap-content."""
    run('foreman-rake foreman_openscap:bulk_upload:default', warn_only=True)


def install_puppet_scap_client():
    """Task to install puppet-foreman_scap_client."""
    run('yum -y install puppet-foreman_scap_client', warn_only=True)


def setup_foreman_discovery(sat_version):
    """Task to setup foreman discovery.

    The following environment variables affect this task:

    * `PXE_DEFAULT_TEMPLATE_URL`
    * `PXELINUX_DISCOVERY_SNIPPET_URL`

    :param str sat_version: contains Satellite version e.g. 6.3
    """
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    if sat_version == 'upstream-nightly':
        # Fetch the upstream-nightly FDI from upstream
        image_url = 'http://downloads.theforeman.org/discovery/nightly/fdi-image-latest.tar'
        run('wget -nv -O- {0} | tar x --overwrite -C /var/lib/tftpboot/boot'.format(image_url))
    else:
        # Since 6.3, installer should install all required packages except FDI
        if float(sat_version) > 6.5:
            # Check BZ 1738199 for final solution (versionlock prevents satellite rpms to install)
            run('foreman-maintain packages unlock')
        run('yum install -y foreman-discovery-image')
        if float(sat_version) > 6.5:
            # Check BZ 1738199 for final solution (versionlock prevents satellite rpms to install)
            run('foreman-maintain packages lock')

    # Unlock the default Locked template for discovery
    run('hammer -u admin -p {0} template update '
        '--name "PXELinux global default" --locked "false"'
        .format(admin_password))
    template_file = run('mktemp')
    # Dump the template
    run('hammer -u admin -p {0} template dump --name "PXELinux global default" > {1}'
        .format(admin_password, template_file))
    if sat_version == '6.3':
        run(r'sed -i -e "s/^ONTIMEOUT\s\+local/ONTIMEOUT discovery/" {0}'.format(template_file))
    else:
        # since 6.4, ONTIMEOUT option uses "default_pxe_item_global" setting
        run('hammer -u admin -p {0} settings set --name '
            '"default_pxe_item_global" --value="discovery"'.format(admin_password))
    run(r'sed -i -e "s/^TIMEOUT\s\+[0-9]\+/TIMEOUT 5/" {0}'.format(template_file))
    # Update the template
    run('hammer -u admin -p {0} template update --name '
        '"PXELinux global default" --type "PXELinux" --file {1}'
        .format(admin_password, template_file))
    run('rm -rf {0}'.format(template_file))


def upgrade_puppet(cdn=False):
    """Upgrades puppet3 to puppet4 and is applicable to Satellite6.3 only

    :param cdn: Indicates whether CDN or Internal Puppet4 repo be used

    Expects the following environment variables:

    PUPPET4_REPO
        The internal puppet4 repository URL.

    """
    if cdn:
        enable_repos('rhel-7-server-satellite-6.3-puppet4-rpms')
    else:
        puppet4_repo = os.environ.get('PUPPET4_REPO')
        if puppet4_repo:
            create_custom_repos(puppet4_repo=puppet4_repo)
    run('satellite-installer --upgrade-puppet')


def disable_baseos_repo():
    """Disable BaseOS Repo if using custom image for vault_requests.


    Expects the following environment variables:

    IMAGE
        The custom image name to be used for vault_requests.
    """
    if os.environ.get('OS_UPGRADE_REPOS'):
        os_version = distro_info()[1]
        disable_repos('rhel-{0}-server-rpms'.format(os_version))


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
    foreman_key_file = '~/.ssh/id_rsa'
    key_url = os.environ.get('LIBVIRT_KEY_URL')
    libvirt_host = os.environ.get('LIBVIRT_HOSTNAME')

    if key_url is None or libvirt_host is None:
        print('You must specify the Libvirt key URL and the Libvirt hostname')
        sys.exit(1)
    # Move existing root user ssh keys, to avoid the ssh key pair mismatch.
    # As only ssh private key is being placed under /root/.ssh/ dir.
    run('mkdir -p /root/.ssh/bkp')
    run('mv /root/.ssh/id_rsa* /root/.ssh/bkp', warn_only=True)
    # Deploy private ssh key under root and foreman account
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
    SERVER_HOSTNAME
        server hostname
    IMAGE_DIR
        path where the generated image will be stored
    CPU_FEATURE
        copies cpu features of base-metal to vm, thus enabling nested_virt
    BRIDGE
        Now Sat6 VM can use isolated VLAN Bridge with static Ip address if
        available, otherwise uses the bridge br0 which provides a dhcp IP
        address from corporate network.
    BRIDGE2
        Specify another bridge to second NIC for the provisioned VM.
    NAT
        the name of NATed network with static IP adressing on custom
        hypervisors where Sat6 VM can be operated too. Typically "foreman"
    IPADDR
        The static IP address from the VLAN which needs to be provided when
        using VLAN Bridge or NAT network.
    NETMASK
        The static netmask of the VLAN when using VLAN Bridge or NAT network
    GATEWAY
        The static gateway of the VLAN when using VLAN Bridge or NAT network

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
        'hostname': os.environ.get('SERVER_HOSTNAME'),
        'image_dir': os.environ.get('IMAGE_DIR'),
        'cpu_feature': os.environ.get('CPU_FEATURE'),
        'bridge': os.environ.get('BRIDGE'),
        'bridge2': os.environ.get('BRIDGE2'),
        'nat': os.environ.get('NAT'),
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

    if options['hostname']:
        command_args.append('--hostname {hostname}')

    if options['image_dir']:
        command_args.append('-p {image_dir}')

    if options['cpu_feature']:
        command_args.append('--cpu-feature {cpu_feature}')

    if options['nat']:
        command_args.append('-n network={nat}')
    elif options['bridge']:
        command_args.append('-n bridge={bridge}')
    else:
        command_args.append('-n bridge=br0')

    if options['bridge2']:
        command_args.append('--network2 bridge={bridge2}')

    if options['ip_addr']:
        command_args.append('--static-ipaddr {ip_addr}')

    if options['netmask']:
        command_args.append('--static-netmask {netmask}')

    if options['gateway']:
        command_args.append('--static-gateway {gateway}')

    command = ' '.join(command_args).format(**options)
    run(command)

    # Give some time to machine boot
    time.sleep(120)

    # Discover IP via ping only when using bridge br0 which provides a DHCP IP
    # from corporate network. Otherwise IP information carries IPADDR env var
    if not options['ip_addr']:
        result = run('ping -c 1 {0}.local'.format(options['target_image']))
        env['vm_ip'] = result.split('(')[1].split(')')[0]
    else:
        env['vm_ip'] = '{ip_addr}'.format(**options)

    # If no hostname is specified compose it from target and default domain.
    # Otherwise hostname is brought in by SERVER_HOSTNAME env var
    if not options['hostname']:
        env['vm_domain'] = '{target_image}.{vm_domain}'.format(**options)
    else:
        env['vm_domain'] = '{hostname}'.format(**options)

    # fix_hostname only if using VLAN Bridge.
    if options['bridge'] != 'br0':
        # We need to fix the /etc/hosts file for snap-guest changes.
        execute(
            fix_hostname,
            entry_domain=env['vm_domain'],
            host_ip=env['vm_ip'],
            host=env['vm_ip'],
        )

    # Execute setup_ddns only if using bridge br0 and foreman (In case of internal
    # libvirt provisioning) with dynamic IP
    if (
        options['bridge'] in ['br0', 'foreman'] and
        'DDNS_HASH' in os.environ and 'DDNS_PACKAGE_URL' in os.environ
    ):
        execute(
            setup_ddns,
            env['vm_domain'],
            env['vm_ip'],
            host=env['vm_ip']
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
        ifcfg_br0.write(u'\n')
        ifcfg_br0.write(u'DEVICE=br0\n')
        ifcfg_br0.write(u'BOOTPROTO=dhcp\n')
        ifcfg_br0.write(u'ONBOOT=yes\n')
        ifcfg_br0.write(u'TYPE=Bridge\n')
        ifcfg_br0.write(u'NM_CONTROLLED=no\n')
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


def configure_osp(forward_zone=None, reverse_zone=None):
    """Configure the named service for OSP Compute Resource.

    Expects the following environment variables:

    OSP_REVERSE_ZONE
        Reverse zone values Example: "179.29.10 178.28.10 177.27.10".

    OSP_FORWARD_ZONE
        Forward zone value Example: "lab.hyd.redhat.com".

    """
    zone_file = '/etc/named/zones.conf'
    if reverse_zone is None:
        reverse_zone = os.environ.get('OSP_REVERSE_ZONE')
    if forward_zone is None:
        forward_zone = os.environ.get('OSP_FORWARD_ZONE')
    run('rm -f /root/zones_cons.conf', warn_only=True)
    run('rm -f /root/zones-pre_osp.conf', warn_only=True)
    run('cp {0} /root/zones-pre_osp.conf'.format(zone_file))
    run('for i in {0}; do satellite-installer '
        '--foreman-proxy-dns-reverse $i.in-addr.arpa ; '
        'sed -n 1,7p {1} >> /root/zones_cons.conf ; done'
        .format(reverse_zone, zone_file))
    run('satellite-installer --foreman-proxy-dns-zone {0}'
        .format(forward_zone))
    run('sed -n 8,14p {0} >> /root/zones_cons.conf'.format(zone_file))
    run('cat /root/zones_cons.conf > {0}'.format(zone_file))
    run('cat /root/zones-pre_osp.conf >> {0}'.format(zone_file))
    run('service named restart')


def generate_capsule_certs(capsule_fqdn=None, sat_version=None):
    """Generate Capsule Certs required for Capsule Installation.

    CAPSULE_FQDN
        CAPSULE FQDN for which certs needs to be created.
    SATELLITE_VERSION
        SATELLITE_VERSION for which the capsule certs needs to be created.

    """
    capsule_fqdn = capsule_fqdn or os.environ.get('CAPSULE_FQDN')
    sat_version = sat_version or os.environ.get('SATELLITE_VERSION')

    run('capsule-certs-generate --foreman-proxy-fqdn {0}'
        ' --certs-tar "/var/www/html/pub/{0}-certs.tar" > '
        '/var/www/html/pub/{0}-out.txt'
        .format(capsule_fqdn))
    run('cat /var/www/html/pub/{0}-out.txt|'
        'grep -v help | grep -v log | grep -A 10 "satellite-installer'
        ' --scenario capsule" > /var/www/html/pub/capsule_script.sh'
        .format(capsule_fqdn))
    run('chmod +x /var/www/html/pub/capsule_script.sh')
    run('sed -i \'s|/var/www/html/pub/{0}-certs.tar|/root/{0}-certs.tar|\' '
        '"/var/www/html/pub/capsule_script.sh"'
        .format(capsule_fqdn))


def setup_capsule(satellite_fqdn=None, capsule_fqdn=None, capsule_org=None,
                  capsule_ak=None):
    """Setup and install the pre-requisites required for Capsule.

    SATELLITE_FQDN
        SATELLITE FQDN from which the certs.tar and capsule_script.sh needed.
    CAPSULE_FQDN
        CAPSULE FQDN for which the certs.tar has been generated.

    """
    os_version = distro_info()[1]
    satellite_fqdn = satellite_fqdn or os.environ.get('SATELLITE_FQDN')
    capsule_fqdn = capsule_fqdn or os.environ.get('CAPSULE_FQDN')
    capsule_org = capsule_org or "Default_Organization"
    capsule_ak = capsule_ak or "ak-capsule-{0}".format(os_version)
    # Disable Beaker Repos.
    disable_beaker_repos(silent=True)

    subscribe(autosubscribe=True)
    install_prerequisites()
    run('yum -y install wget', warn_only=True)
    # Clean up
    unsubscribe()

    # Clean up and install with basic packages.
    clean_rhsm()

    # Install the cert file
    run('yum -y localinstall http://{0}/pub/katello-ca-consumer-latest.noarch.rpm'
        .format(satellite_fqdn))
    run('wget -O /root/capsule_script.sh http://{0}/pub/capsule_script.sh'
        .format(satellite_fqdn))
    run('wget -O /root/{1}-certs.tar http://{0}/pub/{1}-certs.tar'
        .format(satellite_fqdn, capsule_fqdn))
    run('chmod +x /root/capsule_script.sh')

    # Register and subscribe
    print('Register/Subscribe using Subscription-manager.')
    cmd = (
        'subscription-manager register --force --org="{0}" '
        '--activationkey="{1}"'.format(capsule_org, capsule_ak)
    )
    run(cmd)
    # Refresh subscriptions and clean up YUM
    print('Refreshing Subscription-manager.')
    run('subscription-manager refresh')
    print('Performing yum clean up.')
    run('yum clean all', quiet=True)

    run('yum -y update')

    run('yum -y install katello-agent')

    # Ensure Capsule and Satellite6 Server time is in sync.
    manage_daemon('stop', 'chronyd', warn_only=True)
    manage_daemon('stop', 'ntpd', warn_only=True)
    run('ntpdate clock.redhat.com')

    # Install and run satellite-installer to configure capsule.
    run('yum -y install satellite-capsule')
    run('/root/capsule_script.sh')


def cleanup_idm(hostname, idm_password=None):
    """Clean up the IDM server of any previous entries.

    Expects the following environment variables:

    IDM_PASSWORD
        IDM Server Password to fetch a token.

    """
    if idm_password is None:
        idm_password = os.environ.get('IDM_PASSWORD')
    if hostname is None:
        print('Please provide the hostname entry to delete.')
        sys.exit(1)
    run('echo {0} | kinit admin'.format(idm_password))
    run('ipa host-del {0}'.format(hostname), warn_only=True)


def enroll_idm(idm_password=None):
    """Enroll the Satellite6 Server to an IDM Server.

    Expects the following environment variables:

    IDM_PASSWORD
        IDM Server Password to fetch a token.

    """
    # NOTE: Works only when Satellite6 and IDM domains are same and the
    # first nameserver in /etc/resolv.conf file points to the IDM server.
    if idm_password is None:
        idm_password = os.environ.get('IDM_PASSWORD')
    run('yum install -y ipa-client ipa-admintools')
    run('ipa-client-install --password={0} --principal admin '
        '--unattended --no-ntp'.format(idm_password))
    result = run('id admin')
    if result.succeeded:
        print('Enrollment of Satellite6 Server to IDM is successfully '
              'completed.')


def configure_idm_external_auth(idm_password=None):
    """Configure the Satellite6 Server for External Authentication.

    Expects the following environment variables:

    IDM_PASSWORD
        IDM Server Password to fetch a token.

    """
    result = run('id admin')
    if result.failed:
        print('Please execute enroll_idm before configuring External Auth')
        sys.exit(1)
    if idm_password is None:
        idm_password = os.environ.get('IDM_PASSWORD')
    run('echo {0} | kinit admin'.format(idm_password))
    run('ipa service-add HTTP/$(hostname)')
    run('satellite-installer --foreman-ipa-authentication=true')
    run('katello-service restart')


def enroll_ad(ad_passwd=None, ad_server_ip=None, realm=None):
    """Enroll the Satellite6 Server to an AD Server.

    Expects the following environment variables:

    AD_PASSWORD
        AD Server Password to fetch a token.
    VM_DOMAIN
        The domain name of the AD Server.
    AD_SERVER_IP
        The AD Server's IP address.

    """
    # NOTE: Works only when Satellite6 and Windows AD Server domains are
    # same and the first nameserver in /etc/resolv.conf file points to the
    # AD server.
    if realm is None:
        domain = os.environ.get('VM_DOMAIN')
        realm = domain.upper()
    if ad_passwd is None:
        ad_passwd = os.environ.get('AD_PASSWORD')
    if ad_server_ip is None:
        ad_server_ip = os.environ.get('AD_SERVER_IP')
    run('yum install -y gssproxy nfs-utils')
    run('yum install -y sssd adcli realmd ipa-python samba-common-tools')
    run('chattr -i /etc/resolv.conf')
    run('sed -i \'0,/nameserver/{{s/nameserver.*/nameserver {0}/}}\' '
        '/etc/resolv.conf'.format(ad_server_ip))
    run('katello-service restart')
    run('echo {0} | realm join -v {1}'
        .format(ad_passwd, realm))
    run('realm list')
    result = run('id administrator@{0}'.format(realm))
    if result.succeeded:
        print('Enrollment of Satellite6 Server to AD is successfully '
              'completed.')


def configure_ad_external_auth(ad_passwd=None, realm=None):
    """Configure the Satellite6 Server for AD External Authentication.

    Expects the following environment variables:

    AD_PASSWORD
        AD Server Password to fetch a token.
    VM_DOMAIN
        The domain name of the AD Server.

    """
    if realm is None:
        domain = os.environ.get('VM_DOMAIN')
        realm = domain.upper()
        workgroup = realm.split('.')[0]
    result = run('id administrator@{0}'.format(realm))
    if result.failed:
        print('Please execute enroll_ad before configuring External Auth')
        sys.exit(1)
    if ad_passwd is None:
        ad_passwd = os.environ.get('AD_PASSWORD')
    run('yum install -y krb5-workstation')
    run('echo {0} | kinit administrator@{1}'.format(ad_passwd, realm))
    run('mkdir -p /etc/ipa/')
    ipa_default = StringIO()
    ipa_default.write(u'[global]\n')
    ipa_default.write(u'server = unused\n')
    ipa_default.write(u'realm = {0}\n'.format(realm))
    put(local_path=ipa_default,
        remote_path='/etc/ipa/default.conf')
    ipa_default.close()
    net_keytab = StringIO()
    net_keytab.write(u'[global]\n')
    net_keytab.write(u'workgroup = {0}\n'.format(workgroup))
    net_keytab.write(u'realm = {0}\n'.format(realm))
    net_keytab.write(u'kerberos method = system keytab\n')
    net_keytab.write(u'security = ads\n')
    put(local_path=net_keytab,
        remote_path='/etc/net-keytab.conf')
    net_keytab.close()
    run('echo {0} | KRB5_KTNAME=FILE:/etc/gssproxy/http.keytab '
        'net ads keytab add HTTP -U administrator -d3 -s /etc/net-keytab.conf'
        .format(ad_passwd))
    run('chown root:root /etc/gssproxy/http.keytab')
    run('touch /etc/httpd/conf/http.keytab')
    run('satellite-installer --foreman-ipa-authentication=true')
    run('systemctl restart gssproxy.service')
    run('systemctl enable gssproxy.service')
    httpd_service = StringIO()
    httpd_service.write(u'.include /lib/systemd/system/httpd.service\n')
    httpd_service.write(u'[Service]\n')
    httpd_service.write(u'Environment=GSS_USE_PROXY=1\n')
    put(local_path=httpd_service,
        remote_path='/etc/systemd/system/httpd.service')
    httpd_service.close()
    run('systemctl daemon-reload')
    run('systemctl restart httpd.service')


def configure_realm(admin_password=None, keytab_url=None, realm=None,
                    idm_server_ip=None):
    """Configure the Satellite6 Server for REALM Integration

    Expects the following environment variables:

    IDM_SERVER_IP
        IP Address of the IDM Server.
    VM_DOMAIN
        The domain name of the IDM Server.
    KEYTAB_URL
        The URL from which to fetch the Keytab file.
    ADMIN_PASSWORD
        The admin password for Satellite 6.

    """
    if idm_server_ip is None:
        idm_server_ip = os.environ.get('IDM_SERVER_IP')
    domain = os.environ.get('VM_DOMAIN')
    result = run('id admin')
    if result.failed:
        print('Please execute enroll_idm before configuring External Auth')
        sys.exit(1)
    if keytab_url is None:
        keytab_url = os.environ.get('KEYTAB_URL')
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    if realm is None:
        realm = domain.upper()
    run('yum install -y wget')
    run('wget -O /root/freeipa.keytab {0}'.format(keytab_url))
    run('mv /root/freeipa.keytab /etc/foreman-proxy')
    run('chown foreman-proxy:foreman-proxy /etc/foreman-proxy/freeipa.keytab')
    run('satellite-installer --foreman-proxy-realm true '
        '--foreman-proxy-realm-principal realm-proxy@{0} '
        '--foreman-proxy-dhcp-nameservers {1}'.format(realm, idm_server_ip))
    run('cp /etc/ipa/ca.crt /etc/pki/ca-trust/source/anchors/ipa.crt')
    run('update-ca-trust enable ; update-ca-trust')
    run('service foreman-proxy restart')


def apply_hotfix():
    """Apply a hotfix for the Satellite6 Server

    Expects the following environment variables:

    HOTFIX
        Specifies the choice for the hotfix, the default or custom.
    HTTP_SERVER_HOSTNAME
        Specify the hostname of the HTTP Server.
    """
    os_version = distro_info()[1]
    http_server = os.environ.get('HTTP_SERVER_HOSTNAME')
    hotfix = os.environ.get('HOTFIX')
    if hotfix == 'DEFAULT':
        run('katello-service stop')
        run('wget -O /etc/yum.repos.d/hotfix.repo '
            '{0}/pub/hotfix/hotfix_rhel{1}.repo'
            .format(http_server, os_version))
        run('yum -y update')
        run('satellite-installer --upgrade')
    elif hotfix == 'CUSTOM':
        run('wget -0 /root/hotfix.sh '
            '{0}/pub/hotfix/hotfix_rhel{1}.sh'
            .format(http_server, os_version))
        run('chmod +x /root/hotfix.sh')
        run('/root/hotfix.sh')


def upstream_install(admin_password=None, run_katello_installer=True):
    """Task to install Foreman nightly using forklift scripts"""
    koji = 'koji' in os.environ.get('DISTRIBUTION', '').lower()
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    enable_repos('rhel-*-server-extras-rpms', 'rhel-*-server-optional-rpms')
    # Install required packages for the installation
    epel_present = run('rpm -q epel-release', warn_only=True).return_code == 0
    if not epel_present:
        run('rpm -iv http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm')
    run('yum -y install ansible git')
    run('rm -rf forklift')
    run('git clone -q https://github.com/theforeman/forklift.git')

    with cd('forklift'):
        run('ansible-playbook -c local -i,$(hostname) '
            '-e katello_version=nightly {0} {1} '
            '-e foreman_installer_skip_installer=True '
            'playbooks/katello.yml'.format(
                '-e foreman_repositories_environment=staging' if koji else '',
                '-e katello_repositories_environment=staging' if koji else '',
            ))

    # Install support for various compute resources in upstream
    compute_resources = [
        'ec2',
        'gce',
        'libvirt',
        'openstack',
        'ovirt',
        'rackspace',
        'vmware',
    ]
    # Install hammer plugins to match downstream set of plugins
    hammer_plugins = [
        'csv',
        'foreman_admin',
        'foreman_discovery',
        'foreman_openscap',
        'foreman_remote_execution',
        'foreman_virt_who_configure',
    ]
    run('yum install -y foreman-{{{0}}} tfm-rubygem-hammer_cli_{{{1}}}'.format(
        ','.join(compute_resources),
        ','.join(hammer_plugins),
    ))
    # In koji installer modules often don't match with foreman-installer cache
    # By providing some gems the installer cache gets automatically regenerated
    if koji:
        run('/opt/puppetlabs/puppet/bin/gem install puppet-strings')

    installer_options = {
        'foreman-initial-admin-password': admin_password,
        'disable-system-checks': None,
    }
    if run_katello_installer:
        katello_installer(**installer_options)
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
        URL for the Satellite compose repository.
    MAINTAIN_BASE_URL
        URL for the satellite maintenance compose repository
    SATELLITE_VERSION
        Satellite version.

    """
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    base_url = os.environ.get('BASE_URL')
    if base_url is None:
        print('The BASE_URL environment variable should be defined')
        sys.exit(1)

    maintain_url = os.environ.get('MAINTAIN_BASE_URL')
    if maintain_url is None:
        print('The MAINTAIN_BASE_URL environment variable should be defined')
        sys.exit(1)

    satellite_repo = StringIO()
    satellite_repo.write(u'[satellite]\n')
    satellite_repo.write(u'name=satellite\n')
    satellite_repo.write(u'baseurl={0}\n'.format(base_url))
    satellite_repo.write(u'enabled=1\n')
    satellite_repo.write(u'gpgcheck=0\n')
    put(local_path=satellite_repo,
        remote_path='/etc/yum.repos.d/satellite.repo')
    satellite_repo.close()

    create_custom_repos(maintain_repo=maintain_url)

    # Install required packages for the installation
    run('yum install -y satellite')
    if float(os.environ.get('SATELLITE_VERSION')) > 6.5:
        installer_options = {
            'foreman-initial-admin-password': admin_password,
        }
    else:
        installer_options = {
            'foreman-admin-password': admin_password,
        }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def repofile_install(admin_password=None, run_katello_installer=True,
                     repo_url=None):
    """Task to install Satellite 6.3 and 6.4 via repo files

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    REPO_FILE_URL
        URL for the compose repository file to fetch.
    SATELLITE_VERSION
        Satellite version.
    """
    os_version = distro_info()[1]
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    if repo_url is None:
        repo_url = os.environ.get('REPO_FILE_URL')

    run('yum install -y wget')
    run('wget -O /etc/yum.repos.d/satellite6.repo {0}'.format(repo_url))

    # Enable required repository
    run('subscription-manager repos --enable rhel-{0}-server-optional-rpms'
        .format(os_version))

    # Install required packages for the installation
    run('yum install -y satellite')

    if float(os.environ.get('SATELLITE_VERSION')) > 6.5:
        installer_options = {
            'foreman-initial-admin-password': admin_password,
        }
    else:
        installer_options = {
            'foreman-admin-password': admin_password,
        }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def ak_install(admin_password=None, run_katello_installer=True):
    """Task to install Satellite 6.3 and 6.4 via Activation Keys

    The following environment variables affect this command:

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    SATELLITE_VERSION
        Satellite version.
    """
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    # Install required packages for the installation
    run('yum install -y satellite')

    if float(os.environ.get('SATELLITE_VERSION')) > 6.5:
        installer_options = {
            'foreman-initial-admin-password': admin_password,
        }
    else:
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

    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    SATELLITE_VERSION
        Satellite version.

    """
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    # Install required packages for the installation
    run('yum install -y satellite')
    if float(os.environ.get('SATELLITE_VERSION')) > 6.5:
        installer_options = {
            'foreman-initial-admin-password': admin_password,
        }
    else:
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

    ISO_URL or BASE_URL
        The URL where the ISO will be downloaded.
    ADMIN_PASSWORD
        Optional, defaults to 'changeme'. Foreman admin password.
    CHECK_GPG_SIGNATURES
       Optional, all values other than 'true' will default to 'false'.
    SATELLITE_VERSION
        Satellite version.
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

    # Create a mountpoint for ISO
    run('mkdir -p ~/ISO')
    # Download and mount the ISO
    run('mount {0} ~/ISO -t iso9660 -o loop'.format(iso_download(iso_url)))
    # ...and run the installer script.
    with cd('~/ISO'):
        if check_gpg_signatures is True:
            run('./install_packages')
        else:
            run('./install_packages --nogpgsigs')

    if float(os.environ.get('SATELLITE_VERSION')) > 6.5:
        installer_options = {
            'foreman-initial-admin-password': admin_password,
        }
    else:
        installer_options = {
            'foreman-admin-password': admin_password,
        }
    if run_katello_installer:
        katello_installer(**installer_options)
        # Ensure that the installer worked
        run('hammer -u admin -p {0} ping'.format(admin_password))
    else:
        return installer_options


def product_install(distribution, create_vm=False, certificate_url=None,
                    selinux_mode=None, sat_version=None,
                    test_in_stage=False, puppet4='no'):
    """Task which install every product distribution.

    The following environment variables affect this command:

    RHN_USERNAME
        Red Hat Network username.
    RHN_PASSWORD
        Red Hat Network password.
    RHN_POOLID
        Optional. Red Hat Network pool ID. Determines what software will be
        available from RHN.
    SATELLITE_VERSION
        Satellite version.

    Product distributions are satellite6-cdn, satellite6-downstream,
    satellite6-iso or satellite6-upstream, satellite6-koji

    If ``create_vm`` is True then ``vm_destroy`` and ``vm_create`` tasks will
    be run. Make sure to set the required environment variables for those
    tasks.
    Also, if one of the ``setup_ddns`` required environment variables
    is set then that task will only run if the VM does not use any VLAN Bridges

    If ``certificate_url`` parameter or ``FAKE_MANIFEST_CERT_URL`` env var is
    defined the setup_fake_manifest_certificate task will run.

    ``PUPPET4_REPO`` env var can be defined to setup a Puppet4 repository
    prior Satellite installation

    ``OS_UPGRADE_REPOS`` env var can be defined to setup a custom repository or
    repositories (space-separated list) before OS upgrade, typically OS-
    candidate repo when tesing OS compatibility.

    Every call to a task after the definition ``host = env.get('vm_ip',
    env['host'])`` must be run by using ``execute`` and passing ``host=host``.

    :param str distribution: product distribution wanted to install
    :param bool create_vm: creates a virtual machine and then install the
        product on it. Default: False.
    :param str certificate_url: where to fetch a fake certificate.
    :param sat_version: Indicates which satellite version should be installed
    :param puppet4: Indicates what puppet to install with Satellite 6.3
        Default: 'no', 'yes', 'upgrade'

    """
    # Fetch the Satellite Version information.
    sat_version = sat_version or os.environ.get('SATELLITE_VERSION')

    # Honour puppet4 flag only for 6.3, set 'no' for all other sat versions
    puppet4 = puppet4 if sat_version == '6.3' else 'no'

    # Command-line arguments are passed in as strings.
    if isinstance(create_vm, str):
        create_vm = (create_vm.lower() == 'true')
    if isinstance(test_in_stage, str):
        test_in_stage = (test_in_stage.lower() == 'true')

    install_tasks = {
        'satellite6-beta': cdn_install,
        'satellite6-cdn': cdn_install,
        'satellite6-downstream': downstream_install,
        'satellite6-repofile': repofile_install,
        'satellite6-activationkey': ak_install,
        'satellite6-iso': iso_install,
        'satellite6-upstream': upstream_install,
        'satellite6-koji': upstream_install,
    }
    distribution = distribution.lower()

    distributions = install_tasks.keys()
    installer_options = {}

    if distribution not in distributions:
        print('distribution "{0}" should be one of {1}'.format(
            distribution, ', '.join(distributions)))
        sys.exit(1)

    if (
        distribution == 'satellite6-cdn' and
        sat_version not in ('6.3', '6.4', '6.5')
    ):
        raise ValueError(
            "Satellite version should be in [6.3, 6.4, 6.5]"
        )

    if selinux_mode is None:
        selinux_mode = os.environ.get('SELINUX_MODE', 'enforcing')

    if distribution == 'satellite6-iso':
        iso_url = os.environ.get('ISO_URL')
        if iso_url is None:
            print('The ISO_URL environment variable should be defined')
            sys.exit(1)

    if create_vm:
        target_image = os.environ.get('TARGET_IMAGE')
        if not target_image:
            print('The TARGET_IMAGE environment variable should be defined')
            sys.exit(1)

        execute(vm_destroy, target_image, delete_image=True)
        execute(vm_create)
    else:
        # if host already exists (vm_create=False) still fix hostname
        execute(fix_hostname)

    # When creating a vm the vm_ip will be set, otherwise use the fabric host
    host = env.get('vm_ip', env['host'])

    # If we are using activationkey, subscribe to dogfood server
    # otherwise subscribe to CDN
    if distribution == 'satellite6-activationkey':
        execute(subscribe_dogfood, host=host)
    else:
        execute(subscribe, stage=test_in_stage, host=host)
        # Enable repos for Satellite and disable other ones
        execute(enable_satellite_repos,
                cdn=distribution.endswith('cdn'),
                beta=distribution.endswith('beta'),
                sat_version=sat_version,
                puppet4=puppet4,
                host=host)

    # Disable BaseOS if using custom image for vault_requests.
    execute(disable_baseos_repo, host=host)
    # Setting yum stdout log level to be less verbose
    execute(set_yum_debug_level, host=host)
    # Install some basic packages
    execute(update_basic_packages, host=host)
    # Check hostname and start ntpd
    execute(install_prerequisites, host=host)
    # If defined, create custom repo with RHEL candidate for OS upgrade
    # OS_UPGRADE_REPOS can be space-separated list of multiple custom repo urls
    if os.environ.get('OS_UPGRADE_REPOS'):
        custom_repos = os.environ.get('OS_UPGRADE_REPOS').split()
        # this comprehension creates a dict { 'reponame': 'repourl_1, ...}
        custom_repos_dict = {
            'custom_repo_{}'.format(k+1): v
            for (k, v) in zip(range(len(custom_repos)), custom_repos)
        }
        execute(create_custom_repos, host=host, **custom_repos_dict)
    # Update the machine
    execute(update_packages, host=host, warn_only=True)

    execute(setenforce, selinux_mode, host=host)

    execute(setup_satellite_firewall, host=host)

    execute(setup_avahi_discovery, host=host)

    execute(run_command, os.environ.get('FIX_PREINSTALL'), host=host)
    # Sat6.3: enable *internal* puppet4 repo to perform fresh p4 install
    if puppet4 == 'yes' and not distribution.endswith('cdn'):
        puppet4_repo = os.environ.get('PUPPET4_REPO')
        if puppet4_repo:
            execute(create_custom_repos, puppet4_repo=puppet4_repo, host=host)

    # execute returns a dictionary mapping host strings to the given task's
    # return value
    installer_options.update(execute(
        install_tasks[distribution],
        host=host, run_katello_installer=False
    )[host])

    # When using VLAN Bridges os.environ.get('BRIDGE') is 'true' and
    # executes with 'interface=eth0' for Satellite6-automation.
    # When using Satellite6-installer one can specify custom interface.
    if (os.environ.get('BRIDGE') or
            os.environ.get('NAT') or os.environ.get('INTERFACE')):
        # For Client provisioning using Internal Capsule within Lab only
        execute(setup_firewall, {'udp': (67,)}, flush=False, host=host)
        # If an INTERFACE is specified it will be used otherwise would
        # default to eth0 interface. Helpful for configuring DHCP and
        # DNS capsule services.
        interface = os.environ.get('INTERFACE', 'eth0')
    else:
        # Setup libvirt and fetch virtual bridge information
        interface = execute(setup_default_libvirt, host=host)[host]
    # execute returns a dictionary mapping host strings to the given
    # task's return value
    installer_options.update(execute(
        setup_default_capsule,
        host=host, interface=interface, run_katello_installer=False
    )[host])

    # enable ostree feature
    installer_options.update({'katello-enable-ostree': 'true'})

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
        ins_opt_dict = dict(
            i.split('=') if '=' in i else [i, None] for i in ins_opt.split(',')
        )
        installer_options.update(ins_opt_dict)

    execute(
        katello_installer,
        host=host,
        distribution=distribution,
        sat_version=sat_version,
        **installer_options
    )

    execute(run_command, os.environ.get('FIX_POSTINSTALL'), host=host)

    # Temporary workaround to solve pulp message bus connection issue
    # only for 6.1 and above
    if (sat_version not in ('6.0', '6.1', '6.2', '6.3', '6.4')):
        execute(set_service_check_status, host=host)

    certificate_url = certificate_url or os.environ.get(
        'FAKE_MANIFEST_CERT_URL')
    if certificate_url is not None:
        execute(
            setup_fake_manifest_certificate,
            certificate_url,
            host=host
        )
    execute(setup_alternate_capsule_ports, host=host)

    execute(setup_default_docker, host=host)
    execute(katello_service, 'restart', host=host)
    # if we have ssh key to libvirt machine we can setup access to it
    if os.environ.get('LIBVIRT_KEY_URL') is not None:
        execute(setup_libvirt_key, host=host)
    if sat_version == 'upstream-nightly':
        execute(install_puppet_scap_client, host=host)
        execute(install_ansible_scap_client, host=host)
    execute(oscap_content, host=host)
    # setup_foreman_discovery
    # setup_discovery_task needs to be run at last otherwise, any other
    # tasks like ostree which is re-running installer would re-set the
    # discovery templates as well. Please see #1387179 for more info.
    execute(setup_foreman_discovery, sat_version=sat_version, host=host)
    execute(setup_default_subnet, sat_version=sat_version, host=host)
    if sat_version not in ('6.3', '6.4'):
        execute(setup_bfa_prevention, host=host)
    execute(fix_qdrouterd_listen_to_ipv6, host=host)

    if create_vm and 'base' in target_image:
        # Setup Python Code Coverage only for the provisoning jobs.
        execute(setup_python_code_coverage, host=host)

    if os.environ.get('RUBY_CODE_COVERAGE') == 'true':
        # Setup Ruby Code Coverage only for the provisioning jobs.
        execute(setup_ruby_code_coverage, host=host)

        # Configure for Ruby System Code Coverage.
        execute(setup_rubysys_code_coverage, host=host)

        # Configure for Ruby TFM Code Coverage.
        execute(setup_rubytfm_code_coverage, host=host)

    if (
        os.environ.get('EXTERNAL_AUTH') == 'IDM' or
        os.environ.get('IDM_REALM') == 'true'
    ):
        sat6_hostname = os.environ.get('SERVER_HOSTNAME')
        idm_server_ip = os.environ.get('IDM_SERVER_IP')
        execute(
            cleanup_idm,
            hostname=sat6_hostname,
            host=idm_server_ip
        )
        execute(enroll_idm, host=host)
    if os.environ.get('EXTERNAL_AUTH') == 'IDM':
        execute(configure_idm_external_auth, host=host)
    if os.environ.get('IDM_REALM') == 'true':
        execute(configure_realm, host=host)
    if os.environ.get('EXTERNAL_AUTH') == 'AD':
        execute(enroll_ad, host=host)
        execute(configure_ad_external_auth, host=host)
    # Sat6.3: enable puppet4 repo and perform upgraded p4 install
    if puppet4 == 'upgrade':
        execute(upgrade_puppet, cdn=distribution.endswith('cdn'), host=host)
    if os.environ.get('HOTFIX') != 'NO_HOTFIX':
        execute(apply_hotfix, host=host)
    if bz_bug_is_open(1607793):
        execute(setup_rhv_ca, host=host)


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
    if run('df -P /home | awk \'END{print $NF}\'') == '/home':
        run('umount /home')
        run('lvremove -f /dev/mapper/*home')
        run("sed -i '/\\/home/d' /etc/fstab")
        run('lvresize -f -l +100%FREE /dev/mapper/*root')
        run('if uname -r | grep -q el6; then resize2fs -f /dev/mapper/*root; '
            'else xfs_growfs / && mount / -o inode64,remount; fi')


def fix_hostname(entry_domain=None, host_ip=None):
    """Updates `/etc/hosts` with FQDN and IP."""
    if host_ip and entry_domain:
        # Required when running product-automation.
        host = entry_domain.split('.', 1)[0]
        run('echo "{0} {1} {2}" >> /etc/hosts'
            .format(host_ip, entry_domain, host))
    else:
        # Required for fixing the hostname when using satellite-installer
        ip_addr = run(r"ping -c1 $(hostname) | awk -F\( '/icmp_seq/{print$2}' "
                      r"| awk -F\) '{print$1}'")
        run('echo "{0} $(hostname) $(hostname -s)" >> /etc/hosts'
            .format(ip_addr))


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

    run('yum install -y wget', warn_only=True)

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
                # match either '<hash> *<iso_filename>'
                # or '{MD5|SHA1|SHA256} (<iso_filename>) = <hash>'
                iso_filename = search(r'\w+\s+[\*\(]?([^\s\)]+)', result).group(1)
                break

        if iso_filename is None:
            print('Unable to fetch the ISO filename')
            sys.exit(1)

        iso_url = urljoin(iso_url, iso_filename)
    local_iso_filename = run('mktemp')
    run('wget -nv -O {0} {1}'.format(local_iso_filename, iso_url))
    return local_iso_filename


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
    run("sed -i -e 's/^hostname.*/hostname=subscription.rhsm.redhat.com/' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e 's|^prefix.*|prefix=/subscription|' /etc/rhsm/rhsm.conf")
    run("sed -i -e 's|^baseurl.*|baseurl=https://cdn.redhat.com|' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e "
        "'s/^repo_ca_cert.*/repo_ca_cert=%(ca_cert_dir)sredhat-uep.pem/' "
        "/etc/rhsm/rhsm.conf")


def update_basic_packages():
    """Updates some basic packages before we can run some real tests."""
    update_packages('subscription-manager', 'yum-utils', quiet=True)
    run('yum install -y yum-plugin-security yum-security', quiet=True)
    run('rpm -q subscription-manager')


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
        subscribe(autosubscribe=True)
        update_basic_packages()
        # Clean up
        unsubscribe()

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
        'sed \'s|^[^/]*/\\(.*\\)$|/\\1| ; s|//|| ; s|"||g\') '
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
def katello_installer(debug=False, distribution=None, verbose=True,
                      sat_version='6.3', scenario=None, **kwargs):
    """Runs the installer with ``kwargs`` as command options."""
    # capsule-dns-forwarders should be repeated if setting more than one
    # value check if a list is being received and repeat the option with
    # different values
    extra_options = []

    if sat_version == 'upstream-nightly':
        installer = 'foreman'
        scenario = 'katello'
        extra_options.append('--enable-foreman-plugin-remote-execution')
        extra_options.append('--enable-foreman-proxy-plugin-remote-execution-ssh')  # noqa
        extra_options.append('--enable-foreman-plugin-discovery')
        extra_options.append('--enable-foreman-proxy-plugin-discovery')
        extra_options.append('--enable-foreman-plugin-openscap')
        extra_options.append('--enable-foreman-proxy-plugin-openscap')
        extra_options.append('--enable-foreman-plugin-ansible')
        extra_options.append('--enable-foreman-proxy-plugin-ansible')
    else:  # downstream
        installer = 'satellite'
        scenario = scenario or 'satellite'

    if ('foreman-proxy-dns-forwarders' in kwargs and
            isinstance(kwargs['foreman-proxy-dns-forwarders'], list)):
        forwarders = kwargs.pop('foreman-proxy-dns-forwarders')
        for forwarder in forwarders:
            extra_options.append(
                '--foreman-proxy-dns-forwarders="{0}"'.format(forwarder))

    run('{0}-installer --scenario {1} {2} {3} {4} {5}'.format(
        installer,
        scenario,
        '-d' if debug else '',
        '-v' if verbose else '',
        ' '.join([
            '--{0}="{1}"'.format(key, val) if val else '--{0}'.format(key)
            for key, val in kwargs.items()
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
        exclude = '--exclude {0}'.format(','.join(exclude))
    return run('katello-service {0} {1}'.format(exclude, action))


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


def download_manifest(url=None, consumer=None):
    """Task for downloading the manifest file from customer portal.

    The following environment variables affect this command:

    SM_URL
      Subscription Manager URL (e.g. 'https://subscription.rhsm.redhat.com')
    CONSUMER
        A consumer hash to be used for getting the manifest
    RHN_USERNAME
        Red Hat Network username
    RHN_PASSWORD
        Red Hat Network password

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :returns: a path string to a downloaded manifest file
    """
    user = os.environ.get('RHN_USERNAME')
    password = os.environ.get('RHN_PASSWORD')
    string = u'{0}:{1}'.format(user, password)

    if isinstance(string, str):  # py3
        bytestring = bytes('{0}:{1}'.format(user, password), 'utf-8')
    else:  # py2
        bytestring = bytes('{0}:{1}'.format(user, password))

    base64string = base64.encodestring(bytestring).strip()

    if url is None:
        url = os.environ.get('SM_URL')
    if consumer is None:
        consumer = os.environ.get('CONSUMER')
    manifest_file = run('mktemp --suffix=.zip')

    # we do this as we would otherwise potentially download a manifest which
    # has new metadata (such as new content sets/repos) but does not have the
    # required Entitlement certificates to actually access the content.
    certs_put = ('curl -sk -X PUT -H "Authorization:Basic {0}"'
                 ' {1}/subscription/consumers/{2}/certificates'
                 '?lazy_regen=false').format(
                 base64string.decode('utf-8'), url, consumer)
    run(certs_put)

    command = ('curl -sk -H "Authorization:Basic {0}"'
               ' {1}/subscription/consumers/{2}/export/').format(
               base64string.decode('utf-8'), url, consumer)

    response = run(command + ' -I')
    if ('Content-Disposition: attachment' in response):
        run(command + ' -o {0}'.format(manifest_file))
        return manifest_file
    else:
        raise ValueError('Request has returned no attachment. Check the'
                         ' session and distributor hash')


def validate_manifest(manifest_file):
    """Make sure that manifest contains only subscriptions specified in config file
    specified in environment variable and attach if missing any:
    EXP_SUBS_FILE
        List of subscriptions which are supposed to be in the manifest (one
        subscription name per line). No other subscription is allowed.
    :param manifest_file: Where is the manifest to investigate.
    :return: list with True/False boolean
    """
    exp_subs_file = os.environ.get('EXP_SUBS_FILE', None)
    with open(exp_subs_file, 'r') as fp:
        exp_subs = {}
        exp_subs_details = [r.strip().split(';') for r in fp.readlines() if not r.strip(
        ).startswith('#')]
        for name_list in exp_subs_details:
            exp_subs[name_list[0]] = name_list[1:]

    print("expected subscriptions in {} are {}".format(manifest_file, ' & '.join(exp_subs.keys())))
    rct_output = run("rct cat-manifest --no-content {}".format(manifest_file)).split("\n")
    sub_name_next = False
    current_subs = list()
    for r in rct_output:
        r = r.strip()
        if r == 'Subscription:':
            sub_name_next = True
            continue
        if sub_name_next:
            if r.startswith('Name: '):
                current_subs.append(r[6:])
            sub_name_next = False
    print("current subscriptions in {} are {}".format(manifest_file, ' & '.join(current_subs)))

    response = [True]
    for sub in exp_subs.keys():
        if sub not in current_subs:
            response.append('Yes')
            print("Attaching missing subscription {}".format(sub))
            attach = attach_subscription(pool_id=exp_subs[sub][0], count=exp_subs[sub][1])
            if attach:
                print("Successfully attached subscription {}" .format(sub))
            else:
                return [False]
    return response


def attach_subscription(url=None, consumer=None, pool_id=None, count=None):
    """Task to attach subscription to manifest.

    The following environment variables affect this command:

    SM_URL
      Subscription Manager URL (e.g. 'https://subscription.rhsm.redhat.com')
    CONSUMER
        A consumer hash to be used for getting the manifest
    RHN_USERNAME
        Red Hat Network username
    RHN_PASSWORD
        Red Hat Network password

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param pool_id: A pool ID of subscription
    :param count: A quantity of subscription requires to attach
    :returns: boolean True/False
    """
    user = os.environ.get('RHN_USERNAME')
    password = os.environ.get('RHN_PASSWORD')
    auth_details = u'{0}:{1}'.format(user, password)

    if isinstance(auth_details, str):  # py3
        bytestring = bytes('{0}:{1}'.format(user, password), 'utf-8')
    else:  # py2
        bytestring = bytes('{0}:{1}'.format(user, password))

    base64string = base64.encodestring(bytestring).strip()

    if url is None:
        url = os.environ.get('SM_URL')
    if consumer is None:
        consumer = os.environ.get('CONSUMER')

    if pool_id and count:
        command = ('curl -sk -X POST -H "Authorization:Basic {0}"'
                   ' "{1}/subscription/consumers/{2}/entitlements?pool={3}&quantity={4}"').format(
            base64string.decode('utf-8'), url, consumer, pool_id, count)
        response = run(command)
        return 'updated' in response
    else:
        raise ValueError("Pass values under pool_id and count")


def relink_manifest(manifest_file=None):
    """Links the latest downloaded manifest file to the manifest_latest.zip
    softlink.

    :param manifest_file: Specify the manifest file path.
    """
    if manifest_file is None:
        manifest_file = download_manifest()
        if os.environ.get('EXP_SUBS_FILE', None) is not None:
            validate = validate_manifest(manifest_file)
            assert validate[0]
            if len(validate) > 1:
                manifest_file = download_manifest()
                assert validate_manifest(manifest_file)[0]
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


def set_yum_debug_level(level=1):
    """Set default debug level for yum output"""
    run(
        'sed -i "s/^[#]*debuglevel=.*/debuglevel={0}/" /etc/yum.conf'
        .format(level)
    )


def set_service_check_status(user='admin', password='changeme',
                             value='false'):
    """Set service check status to given value"""
    run(
        'hammer -u {0} -p {1} settings set '
        '--name=check_services_before_actions --value={2}'
        .format(user, password, value)
    )


def setup_alternate_capsule_ports(port_range='9400-14999'):
    """Setup alternate capsule ports in SELINUX and install tunneling tool

    :param port_range: these ports will be added under websm_port_t type.
    """
    # nmap is used by checks for open port during capsule faking
    # nmap's ncat (opposite to nc) supports -c option we use for capsule faking
    # and rhel7 has separate package for ncat named nmap-ncat
    run('which nmap || yum -d1 -y install nmap', warn_only=True)
    # fuser is used to find out available ports to listen on
    run('which fuser || yum -d1 -y install psmisc', warn_only=True)
    # labelling custom port range so that passenger will be allowed to connect
    run('semanage port -a -t websm_port_t -p tcp {0}'.format(port_range), warn_only=True)


def setup_rhv_ca():
    """ Setups and trusts the provided CA cert
    """
    http_server = os.environ.get('HTTP_SERVER_HOSTNAME')
    run('wget {0}/pub/rhevm1-ca.pem -P '
        '/etc/pki/ca-trust/source/anchors/'.format(http_server))
    run('update-ca-trust enable ; update-ca-trust')
    print("RHV CA cert has been successfully added to CA trust")


def configure_telemetry():
    """Setup telemetry on the satellite box with grafana monitoring tool
    """
    http_server = os.environ.get('HTTP_SERVER_HOSTNAME')
    print("Install required packages for PCP")
    run('yum -y install pcp pcp-pmda-apache')
    run('wget {0}/pub/configure_telemetry.sh'.format(http_server))
    print("Configure Apache and hotproc")
    run('chmod 777 configure_telemetry.sh && ./configure_telemetry.sh')
    run('cd /var/lib/pcp/pmdas/proc/ && ./Install <<< c')
    run('cd /var/lib/pcp/pmdas/apache && ./Install <<< 80')
    run('echo "apache::purge_configs: false" '
        '>>/etc/foreman-installer/custom-hiera.yaml')
    run('systemctl restart httpd pmcd pmlogger')
    run('yum -y install foreman-telemetry pcp-mmvstatsd')
    print("Enable telemetry via Statsd protocol")
    run('satellite-installer --foreman-telemetry-statsd-enabled true')
    run('systemctl restart httpd')
    run('systemctl enable pcp-mmvstatsd pmcd pmlogger && '
        'systemctl start pcp-mmvstatsd')
    print("The telemetry metrics matrix")
    run('foreman-rake telemetry:metrics')
    print('Grafana Tool setup')
    run('subscription-manager repos --enable rhel-7-server-optional-rpms')
    run('yum -y install pcp-webapi pcp-webapp-grafana pcp-webapp-vector')
    run('systemctl start pmwebd && systemctl enable pmwebd')
    run('firewall-cmd --add-port=44323/tcp && '
        'firewall-cmd --permanent --add-port=44323/tcp')
