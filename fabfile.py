"""A set of tasks for automating interactions with Satellite servers.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.

"""
from __future__ import print_function
import os
import random
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
    distro = distro_info()[0]
    if distro.lower() != 'rhel':
        return

    # Register the system.
    for env_var in ('RHN_USERNAME', 'RHN_PASSWORD'):
        if env_var not in os.environ:
            print('The {0} environment variable must be set.'.format(env_var))
            sys.exit(1)
    run(
        'subscription-manager register --force --user={0} --password={1} {2}'
        .format(
            os.environ['RHN_USERNAME'],
            os.environ['RHN_PASSWORD'],
            '--autosubscribe' if autosubscribe else ''
        )
    )

    # Subscribe the system if a pool ID was provided.
    rhn_poolid = os.environ.get('RHN_POOLID')
    if rhn_poolid is not None:
        has_pool_msg = (
            'This unit has already had the subscription matching pool ID'
        )
        for _ in range(3):
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
    run(
        "service httpd restart;"
        "service pulp_celerybeat restart;"
        "service pulp_resource_manager restart;"
        "service pulp_workers restart;"
    )

    if distro_info()[1] >= 7:
        # rhel7 replaced iptables with firewalld
        run("yum -y install iptables-services;"
            "systemctl mask firewalld.service;"
            "systemctl enable iptables.service;"
            "systemctl stop firewalld.service;"
            "systemctl start iptables.service;")

    # Satellite 6 IP
    sat_ip = search(
        r'\d+ bytes from (.*):',
        run('ping -c 1 -n $(hostname) | grep "icmp_seq"')
    ).group(1)
    run('iptables -I OUTPUT -d {} -j ACCEPT'.format(sat_ip))

    # PROXY IP
    proxy_ip = search(
        r'\d+ bytes from (.*):',
        run('ping -c 1 -n $(hostname) | grep "icmp_seq"'
            .format(proxy_info.hostname))
    ).group(1)
    run('iptables -I OUTPUT -d {} -j ACCEPT'.format(proxy_ip))

    # Nameservers
    nameservers = run(
        'cat /etc/resolv.conf | grep nameserver | cut -d " " -f 2')
    for entry in nameservers.split('\n'):
        run('iptables -I OUTPUT -d {} -j ACCEPT'.format(entry.strip()))

    # To make the changes persistent across reboots when using the command line
    # use this command:
    run('iptables-save > /etc/sysconfig/iptables')

    run('service iptables restart')

    # Configuring yum to use the proxy
    run('echo "proxy=http://{0}:{1}" >> /etc/yum.conf'
        .format(proxy_info.hostname, proxy_info.port))
    run('echo "proxy_username={}" >> /etc/yum.conf'
        .format(proxy_info.username))
    run('echo "proxy_password={}" >> /etc/yum.conf'
        .format(proxy_info.password))

    # Configuring rhsm to use the proxy
    run('sed -i -e "s/^proxy_hostname.*/proxy_hostname = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.hostname))
    run('sed -i -e "s/^proxy_port.*/proxy_port = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.port))
    run('sed -i -e "s/^proxy_user.*/proxy_user = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.username))
    run('sed -i -e "s/^proxy_password.*/proxy_password = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_info.password))

    # Run the installer
    run('katello-installer -v --foreman-admin-password="changeme" '
        '--katello-proxy-url=http://{0} --katello-proxy-port={1} '
        '--katello-proxy-username={2} '
        '--katello-proxy-password={3}'.format(
            proxy_info.hostname, proxy_info.port,
            proxy_info.username, proxy_info.password
        ))


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
        interface = run(
            'ip addr | grep "state UP" | cut -d ":" -f 2', quiet=True)
        # Aways select the first interface
        interface = interface.split('\n', 1)[0].strip()
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

    uname = run('uname -r')
    if 'el6' in uname:
        run('service tomcat6 restart')
    elif 'el7' in uname:
        run('service tomcat restart')
    else:
        print('Unable to restart tomcat')


def setup_abrt():
    """Task to setup abrt on foreman

    Currently only available on RHEL7, check BZ #1150197 for more info

    """
    # Install required packages for the installation
    run(
        'yum install -y '
        'abrt-cli '
        'rubygem-smart_proxy_abrt '
        'rubygem-smart_proxy_pulp'
    )
    run('service foreman restart')

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
    run('sed -i -e "s/^SSLVerify = no.*/SSLVerify = yes/" '
        '/etc/libreport/plugins/ureport.conf')
    run('sed -i -e "s/^SSLClientAuth = .*/SSLClientAuth = puppet/" '
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

    command = ' '.join(command_args).format(**options)

    run(command)

    # Give some time to machine boot
    time.sleep(60)

    result = run('ping -c 1 {}.local'.format(
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
        run('rm {image_path}'.format(
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
    run('service ntpd start')
    run('chkconfig ntpd on')

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


def install_nightly(admin_password=None, org_name=None, loc_name=None):
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
    run('cd katello-deploy && ./setup.rb --skip-installer '
        'rhel{os_version}'.format(os_version=os_version))
    run('katello-installer -v -d '
        '--foreman-admin-password="{0}" '
        '--foreman-initial-organization="{1}" '
        '--foreman-initial-location="{2}"'
        ''.format(admin_password, org_name, loc_name))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def manage_repos(os_version=None, cdn=False):
    """Enables only required RHEL repos for Satellite 6."""

    if os_version is None:
        print('Please provide the OS version.')
        sys.exit(1)

    if isinstance(cdn, str):
        cdn = (cdn.lower() == 'true')

    # Clean up system if Beaker-based
    run('rm -rf /etc/yum.repos.d/beaker-*')
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
    run('yum update -y', warn_only=True)


def install_satellite(admin_password=None):
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

    # First, subscribe the system
    subscribe()

    # Enable some repos
    manage_repos(os_version, True)

    # Basic configuration
    install_prerequisites()

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


def provision_install(task_name, certificate_url=None):
    """Task to be run by the provisioning job in order to provision a clean
    machine with a fresh Satellite installation.

    According to the ``task_name`` provided, it will install downstream,
    upstream or ISO.

    If ``certificate_url`` parameter or ``FAKE_MANIFEST_CERT_URL`` env var is
    defined the setup_fake_manifest_certificate task will run.

    """
    task_names = ('downstream', 'iso', 'upstream')

    if task_name not in task_names:
        print('task_name "{0}" should be one of {1}'.format(
            task_name, ', '.join(task_names)))
        sys.exit(1)

    target_image = os.environ.get('TARGET_IMAGE')
    if target_image is None:
        print('The TARGET_IMAGE environment variable should be defined')
        sys.exit(1)

    if task_name == 'iso':
        iso_url = os.environ.get('ISO_URL')
        if iso_url is None:
            print('The ISO_URL environment variable should be defined')
            sys.exit(1)

    execute(vm_destroy, target_image, delete_image=True)
    execute(vm_create)
    execute(setup_ddns, env['vm_domain'], env['vm_ip'], host=env['vm_ip'])

    # Register and subscribe machine to Red Hat
    execute(subscribe, host=env['vm_ip'])

    execute(install_prerequisites, host=env['vm_ip'])

    if task_name == 'downstream':
        execute(install_satellite, host=env['vm_ip'])
        execute(setup_default_capsule, host=env['vm_ip'])

    if task_name == 'iso':
        execute(iso_install, iso_url, host=env['vm_ip'])
        execute(setup_default_capsule, host=env['vm_ip'])

    if task_name == 'upstream':
        execute(install_nightly, host=env['vm_ip'])
        if distro_info()[1] == '7':
            execute(setup_abrt, host=env['vm_ip'])
        else:
            print('WARNING: ABRT was not set up')

    certificate_url = certificate_url or os.environ.get(
        'FAKE_MANIFEST_CERT_URL')
    if certificate_url is not None:
        execute(
            setup_fake_manifest_certificate,
            certificate_url,
            host=env['vm_ip']
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

    A `(distro, major_version)` tuple is returned if called as a function.

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
            version = match.group(1).split('.')[0]
        else:
            version = None

        if distro is None or version is None:
            print('Was not possible to fetch distro information')
            sys.exit(1)

        cache[host] = distro, version

    distro, version = cache[host]
    print('{0} {1}'.format(distro, version))
    return distro, version


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
    run('yum update -y subscription-manager yum-utils',
        warn_only=True, quiet=True)
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
            run(
                'yum update -y --advisory "{0}"'.format(rnd_errata),
                quiet=True)
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
    run('service goferd status', warn_only=True)
