import os
import random
import sys
import time

from fabric.api import env, execute, local, put, run
from StringIO import StringIO


def unsubscribe():
    """Unregisters a machine from Red Hat"""
    run('subscription-manager unregister', warn_only=True)
    run('subscription-manager clean')


def subscribe(autosubscribe=False):
    """Registers and subscribes machine to Red Hat."""

    distro = os.environ.get('DISTRO')
    if distro is not None:
        distro = distro.lower()
    else:
        print 'You need to provide a distro.'
        sys.exit(1)

    autosubscribe = '--autosubscribe' if autosubscribe else ''

    if distro.startswith('rhel'):
        rhn_info = {
            'rhn_username': os.environ.get('RHN_USERNAME'),
            'rhn_password': os.environ.get('RHN_PASSWORD'),
            'rhn_poolid': os.environ.get('RHN_POOLID'),
        }

        if any([
            value is None
            for key, value in rhn_info.items()
            if key != 'rhn_poolid'
        ]):
            print('One of RHN_USERNAME, RHN_PASSWORD environment '
                  'variables is not defined')
            sys.exit(1)

        run('subscription-manager register --force'
            ' --user={0[rhn_username]}'
            ' --password={0[rhn_password]}'
            ' {1}'
            ''.format(rhn_info, autosubscribe))

        if rhn_info['rhn_poolid'] is not None:
            run('subscription-manager subscribe --pool={0[rhn_poolid]}'.format(
                rhn_info))


def setup_ddns(entry_domain, host_ip):
    """Task to setup DDNS client

    :param str entry_domain: the FQDN of the host
    :param str entry_hash: host FQDN DDNS entry hash
    :param str host_ip: host IP address

    """
    ddns_hash = os.environ.get('DDNS_HASH')
    if ddns_hash is None:
        print 'The DDNS_HASH environment variable should be defined'
        sys.exit(1)

    ddns_package_url = os.environ.get('DDNS_PACKAGE_URL')
    if ddns_package_url is None:
        print 'The DDNS_PACKAGE_URL environment variable should be defined'
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


def setup_http_proxy():
    """Task to setup HTTP proxy and block non-proxy traffic from your foreman
    server.

    """
    proxy_hostname = os.environ.get('PROXY_HOSTNAME')
    proxy_port = os.environ.get('PROXY_PORT')
    proxy_username = os.environ.get('PROXY_USER')
    proxy_password = os.environ.get('PROXY_PASSWORD')

    eth = run('ping -c 1 $(hostname) | grep "icmp_seq"')
    proxy = run('ping -c 1 {} | grep "icmp_seq"'.format(proxy_hostname))
    nameservers = run(
        'cat /etc/resolv.conf | grep nameserver | cut -d " " -f 2')
    eth = eth.split('(')[1].split(')')[0]
    proxy = proxy.split('(')[1].split(')')[0]

    # Satellite 6 IP
    run('iptables -I OUTPUT -d {} -j ACCEPT'.format(eth))

    # PROXY IP
    run('iptables -I OUTPUT -d {} -j ACCEPT'.format(proxy))

    # Nameservers
    for entry in nameservers.split('\n'):
        run('iptables -I OUTPUT -d {} -j ACCEPT'.format(entry))

    # To make the changes persistent across reboots when using the command line
    # use this command:
    run('iptables-save > /etc/sysconfig/iptables')

    run('service iptables restart')

    # Configuring yum to use the proxy
    run('echo "proxy=http://{}:{}" >> /etc/yum.conf'
        ''.format(proxy_hostname, proxy_port))
    run('echo "proxy_username={}" >> /etc/yum.conf'.format(proxy_username))
    run('echo "proxy_password={}" >> /etc/yum.conf'.format(proxy_password))

    # Configuring rhsm to use the proxy
    run('sed -i -e "s/^proxy_hostname.*/proxy_hostname = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_hostname))
    run('sed -i -e "s/^proxy_port.*/proxy_port = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_port))
    run('sed -i -e "s/^proxy_user.*/proxy_user = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_username))
    run('sed -i -e "s/^proxy_password.*/proxy_password = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_password))

    # Run the installer
    run('katello-installer -v --foreman-admin-password="changeme" '
        '--katello-proxy-url=http://{} --katello-proxy-port={} '
        '--katello-proxy-username={} '
        '--katello-proxy-password={}'.format(
            proxy_hostname, proxy_port, proxy_username, proxy_password
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
        print 'Was not possible to fetch nameserver information'
        sys.exit(1)

    oauth_secret = run(
        'grep oauth_consumer_secret /etc/foreman/settings.yaml | '
        'cut -d " " -f 2', quiet=True).strip()
    if len(oauth_secret) == 0:
        print 'Not able to'

    hostname = run('hostname', quiet=True).strip()
    if len(hostname) == 0:
        print 'Was not possible to fetch hostname information'
        sys.exit(1)

    domain = hostname.split('.', 1)[1]
    if len(domain) == 0:
        print 'Was not possible to fetch domain information'
        sys.exit(1)

    if interface is None:
        interface = run(
            'ip addr | grep "state UP" | cut -d ":" -f 2', quiet=True)
    if len(interface) == 0:
        print 'Was not possible to fetch interface information'
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


def reservation():
    """Task to provision a VM using snap-guest based on a ``SOURCE_IMAGE`` base
    image.

    Expects the following environment variables::

    VM_RAM: RAM memory in MB
    VM_CPU: number of CPU cores
    VM_DOMAIN: VM's domain name
    SOURCE_IMAGE: base image name
    TARGET_IMAGE: target image name

    The VM will have the TARGET_IMAGE.VM_DOMAIN hostname, but make sure to have
    setup DDND entry correctly.

    This task will add to the ``env`` the vm_ip and vm_domain

    """
    options = {
        'vm_ram': os.environ.get('VM_RAM'),
        'vm_cpu': os.environ.get('VM_CPU'),
        'vm_domain': os.environ.get('VM_DOMAIN'),
        'source_image': os.environ.get('SOURCE_IMAGE'),
        'target_image': os.environ.get('TARGET_IMAGE'),
    }

    run('snap-guest -b {source_image} -t {target_image} -m {vm_ram} '
        '-c {vm_cpu} -d {vm_domain} -n bridge=br0 -f'.format(**options))

    # Give some time to machine boot
    time.sleep(60)

    result = run('ping -c 1 {}.local'.format(
        options['target_image']))

    env['vm_ip'] = result.split('(')[1].split(')')[0]
    env['vm_domain'] = '{target_image}.{vm_domain}'.format(**options)


def install_prerequisites():
    """Task to ensure that the prerequisites for installation are in place"""

    # Full forward and reverse DNS resolution using a fully qualified domain
    # name. Check that hostname and localhost resolve correctly, using the
    # following commands:
    run('ping -c1 localhost')
    run('ping -c1 `hostname -s`')
    run('ping -c1 `hostname -f`')

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
        org_name = os.environ.get('LOCATION_NAME', 'Default_Location')

    distro = os.environ.get('DISTRO')

    if distro is None:
        print 'The DISTRO environment variable should be defined'
        sys.exit(1)

    os_version = distro[4]

    run('yum repolist')
    # Make sure to have yum-utils installed
    run('yum install -y yum-utils')
    run('yum-config-manager --disable "*"')
    run('yum-config-manager --enable "rhel-{0}-server-rpms"'.format(
        os_version))
    run('yum-config-manager --enable "rhel-server-rhscl-{0}-rpms"'.format(
        os_version))
    # Install required packages for the installation
    run('yum install -y git ruby')

    run('if [ -d katello-deploy ]; then rm -rf katello-deploy; fi')
    run('git clone https://github.com/Katello/katello-deploy.git')

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('cd katello-deploy && ./setup.rb --skip-installer rhel6')
    run('katello-installer -v -d '
        '--foreman-admin-password="{0}" '
        '--foreman-initial-organization="{1}" '
        '--foreman-initial-location="{2}"'
        ''.format(admin_password, org_name, loc_name))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def install_satellite(admin_password=None):
    """Task to install Satellite 6"""
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    distro = os.environ.get('DISTRO')

    if distro is None:
        print 'The DISTRO environment variable should be defined'
        sys.exit(1)

    base_url = os.environ.get('BASE_URL')

    if base_url is None:
        print 'The BASE_URL environment variable should be defined'
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

    os_version = distro[4]

    # Clean up system if Beaker-based
    run('rm -rf /etc/yum.repos.d/beaker-*')
    run('rm -rf /var/cache/yum*')

    # Disable yum plugin for sub-man
    run('sed -i -e "s/^enabled.*/enabled=0/" '
        '/etc/yum/pluginconf.d/subscription-manager.conf')
    # And disable all repos for now
    run('subscription-manager repos --disable "*"')

    run('subscription-manager repos --enable "rhel-{0}-server-rpms"'.format(
        os_version))
    run('subscription-manager repos --enable "rhel-server-rhscl-{0}-rpms"'
        ''.format(os_version))
    run('yum repolist')

    # Install required packages for the installation
    run('yum install -y katello libvirt')

    # Make sure that SELinux is enabled
    run('setenforce 1')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def reservation_install(task_name, admin_password=None):
    """Task to execute reservation, setup_ddns and install_``task_name``

    The ``admin_password`` parameter will be passed to the
    install_``task_name`` task.

    """
    task_names = ('nightly', 'satellite')

    if task_name not in task_names:
        print 'task_name "{0}" should be one of {1}'.format(
            task_name, ', '.join(task_names))
        sys.exit(1)

    execute(reservation)
    execute(setup_ddns, env['vm_domain'], env['vm_ip'], host=env['vm_ip'])

    # Register and subscribe machine to Red Hat
    execute(subscribe, host=env['vm_ip'])

    execute(install_prerequisites, host=env['vm_ip'])

    if task_name == 'nightly':
        execute(install_nightly, admin_password, host=env['vm_ip'])

    if task_name == 'satellite':
        execute(install_satellite, admin_password, host=env['vm_ip'])

    execute(setup_default_capsule, host=env['vm_ip'])


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


# Miscelaneous tasks ==========================================================
def create_personal_git_repo(name, private=False):
    """Creates a new personal git repository under the public_git repository"""

    # Since all args are turned to string, if no defaults are used...
    if isinstance(private, str):
        private = (private.lower() == 'true')

    repo_name = '{0}.git'.format(name)

    local('git init --bare --shared={0} {1}'
          ''.format('none' if private else 'all', repo_name))

    # Ensure that the public_git directory is created
    run('mkdir -p ~/public_git')
    run('chmod 755 ~/public_git')

    put(repo_name, '~/public_git/'.format(repo_name))

    local('rm -rf {0}'.format(repo_name))


# Client registration
# ==================================================
def clean_rhsm():
    """Removes pre-existing Candlepin certs and resets RHSM."""
    print "Erasing existing Candlepin certs, if any."
    run('yum erase -y $(rpm -qa |grep katello-ca-consumer)',
        warn_only=True, quiet=True)
    print "Resetting rhsm.conf to point to cdn."
    run("sed -i -e 's/^hostname.*/hostname=subscription.rhn.redhat.com/' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e 's/^prefix.*/prefix=\/subscription/' /etc/rhsm/rhsm.conf")
    run("sed -i -e 's/^baseurl.*/baseurl=https:\/\/cdn.redhat.com/' "
        "/etc/rhsm/rhsm.conf")
    run("sed -i -e 's/^repo_ca_cert.*/repo_ca_cert=%(ca_cert_dir)"
        "sredhat-uep.pem/' /etc/rhsm/rhsm.conf")


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
    ak = os.getenv('ACTIVATIONKEY')
    if not ak:
        print "You need to provide an activationkey."
        sys.exit(1)
    # Candlepin cert RPM
    cert_url = os.getenv('CERTURL')
    if not cert_url:
        print "You need to install the Candlepin Cert RPM."
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
    print "Register/Subscribe using Subscription-manager."
    run('subscription-manager register --force'
        ' --org="{0}"'
        ' --activationkey="{1}"'
        ''.format(org, ak))
    print "Refreshing Subscription-manager."
    run('subscription-manager refresh')
    print "Performing yum clean up."
    run('yum clean all', quiet=True)
    print "'Firefox' and 'Telnet' should not be installed."
    run('rpm -q firefox telnet', warn_only=True)
    print "Installing 'Firefox' and 'Telnet'."
    run('yum install -y firefox telnet', quiet=True)
    print "'Firefox' and 'Telnet' should be installed."
    run('rpm -q firefox telnet')
    print "Removing 'Firefox' and 'Telnet'."
    run('yum remove -y firefox telnet', quiet=True)
    print "Checking if 'Firefox' and 'Telnet' are installed."
    run('rpm -q firefox telnet', warn_only=True)
    print "Installing 'Web Server' group."
    run('yum groupinstall -y "Web Server"', quiet=True)
    print "Checking for 'httpd' and starting it."
    run('rpm -q httpd')
    run('service httpd start', warn_only=True)
    print "Stopping 'httpd' service and remove 'Web Server' group."
    run('service httpd stop', warn_only=True)
    run('yum groupremove -y "Web Server"', quiet=True)
    print "Checking if 'httpd' is really removed."
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
            print "Applying errata: {0}".format(rnd_errata)
            # Apply the errata
            run(
                'yum update -y --advisory "{0}"'.format(rnd_errata),
                quiet=True)
        else:
            print "NO ERRATA AVAILABLE"
    else:
        print "FAILED TO OBTAIN ERRATA INFORMATION"
