import os
import sys
import time

from fabric.api import env, execute, put, run
from StringIO import StringIO


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
    proxy_username = os.environ.get('PROXY_USER')
    proxy_password = os.environ.get('PROXY_PASSWORD')

    eth = run('ping -c 1 $(hostname) | grep "icmp_seq"')
    proxy = run('ping -c 1 {} | grep "icmp_seq"'.format(proxy_hostname))
    nameservers = run(
        'cat /etc/resolv.conf | grep nameserver | cut -d " " -f 2')
    eth = eth.split('(')[1].split(')')[0]
    proxy = proxy.split('(')[1].split(')')[0]

    output = StringIO()
    output.write(
        '*filter\n'
        ':INPUT ACCEPT [0:0]\n'
        ':FORWARD ACCEPT [0:0]\n'
        ':OUTPUT ACCEPT [0:0]\n'
        '-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n'
        '-A INPUT -i lo -j ACCEPT\n'
        '-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT\n'
        '-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT\n'
        '-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT\n'
        '-A INPUT -j REJECT --reject-with icmp-host-prohibited\n'
        '-A FORWARD -j REJECT --reject-with icmp-host-prohibited\n'
        '-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n'
        '-A OUTPUT -d 127.0.0.1 -j ACCEPT\n'
    )

    output.write('# Satellite 6 IP\n')
    output.write('-A OUTPUT -d {} -j ACCEPT\n'.format(eth))

    output.write('# PROXY IP\n')
    output.write('-A OUTPUT -d {} -j ACCEPT\n'.format(proxy))

    output.write('# Nameservers\n')
    for entry in nameservers.split('\n'):
        output.write('-A OUTPUT -d {} -j ACCEPT\n'.format(entry))

    output.write('-A OUTPUT -j REJECT --reject-with icmp-host-prohibited\n')
    output.write('COMMIT\n')

    run('cp /etc/sysconfig/iptables /etc/sysconfig/iptables.old')
    print 'Writing {} to /etc/sysconfig/iptables'.format(output.getvalue())
    put(local_path=output, remote_path='/etc/sysconfig/iptables')

    output.close()

    run('service iptables restart')

    # Configuring yum to use the proxy
    run('echo "proxy=http://{}:8888" >> /etc/yum.conf'.format(proxy_hostname))
    run('echo "proxy_username={}" >> /etc/yum.conf'.format(proxy_username))
    run('echo "proxy_password={}" >> /etc/yum.conf'.format(proxy_password))

    # Configuring rhsm to use the proxy
    run('sed -i -e "s/^proxy_hostname.*/proxy_hostname = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_hostname))
    run('sed -i -e "s/^proxy_port.*/proxy_port = 8888/" /etc/rhsm/rhsm.conf')
    run('sed -i -e "s/^proxy_user.*/proxy_user = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_username))
    run('sed -i -e "s/^proxy_password.*/proxy_password = {}/" '
        '/etc/rhsm/rhsm.conf'.format(proxy_password))

    # Run the installer
    run('katello-installer -v --foreman-admin-password="changeme" '
        '--katello-proxy-url=http://{} --katello-proxy-port=8888 '
        '--katello-proxy-username={} '
        '--katello-proxy-password={}'.format(
            proxy_hostname, proxy_username, proxy_password
        ))


def reservation(data=None):
    """Task to provision a VM using snap-guest based on a ``SOURCE_IMAGE`` base
    image.

    Expects the following environment variables::

    VM_RAM: RAM memory in MB
    VM_CPU: number of CPU cores
    VM_DOMAIN: VM's domain name
    DDNS_HASH: DDNS entry hash
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


def install_nightly(admin_password=None):
    """Task to install Foreman nightly using katello-deploy script"""
    if admin_password is None:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    distro = os.environ.get('DISTRO')

    if distro is None:
        print 'The DISTRO environment variable should be defined'
        sys.exit(1)

    if distro.startswith('rhel'):
        rhn_info = {
            'rhn_username': os.environ.get('RHN_USERNAME'),
            'rhn_password': os.environ.get('RHN_PASSWORD'),
            'rhn_poolid': os.environ.get('RHN_POOLID'),
        }
        os_version = distro[4]

        if any([value is None for _, value in rhn_info.items()]):
            print('One of RHN_USERNAME, RHN_PASSWORD, RHN_POOLID environment '
                  'variables is not defined')
            sys.exit(1)

        run('subscription-manager register --force --user={0[rhn_username]} '
            '--password={0[rhn_password]}'.format(rhn_info))
        run('subscription-manager subscribe --pool={0[rhn_poolid]}'.format(
            rhn_info))

    run('yum repolist')
    # Make sure to have yum-utils installed
    run('yum install -y yum-utils')
    run('yum-config-manager --disable "*"')
    run('yum-config-manager --enable "rhel-{0}-server-rpms"'.format(
        os_version))
    run('yum-config-manager --enable "rhel-server-rhscl-{0}-rpms"'.format(
        os_version))
    # Install required packages for the installation
    run('yum install -y git ruby java-1.7.0-openjdk')

    run('if [ -d katello-deploy ]; then rm -rf katello-deploy; fi')
    run('git clone https://github.com/Katello/katello-deploy.git')

    run('setenforce 0')
    run('cd katello-deploy && ./setup.rb --skip-installer rhel6')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))
    run('service iptables stop')

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

    if distro.startswith('rhel'):
        rhn_info = {
            'rhn_username': os.environ.get('RHN_USERNAME'),
            'rhn_password': os.environ.get('RHN_PASSWORD'),
            'rhn_poolid': os.environ.get('RHN_POOLID'),
        }
        os_version = distro[4]

        if any([value is None for _, value in rhn_info.items()]):
            print('One of RHN_USERNAME, RHN_PASSWORD, RHN_POOLID environment '
                  'variables is not defined')
            sys.exit(1)

        run('subscription-manager register --force --user={0[rhn_username]} '
            '--password={0[rhn_password]}'.format(rhn_info))
        run('subscription-manager subscribe --pool={0[rhn_poolid]}'.format(
            rhn_info))

    run('yum repolist')
    # Make sure to have yum-utils installed
    run('rm -rf /etc/yum.repos.d/beaker-*')
    run('rm -rf /var/cache/yum*')

    if distro.startswith('rhel7'):
        run('sed -i -e "s/enabled.*/enabled=0/" '
            '/etc/yum/pluginconf.d/subscription-manager.conf')
        run('sed -i -e "s/enabled.*/enabled = 0/g" '
            '/etc/yum.repos.d/redhat.repo')

    run('yum clean all')
    run('yum install -y yum-utils')
    run('yum-config-manager --disable "*"')
    run('yum-config-manager --enable "rhel-{0}-server-rpms"'.format(
        os_version))
    run('yum-config-manager --enable "rhel-server-rhscl-{0}-rpms"'.format(
        os_version))
    run('yum-config-manager --enable satellite')
    run('yum repolist')

    # Install required packages for the installation
    run('yum install -y java-1.7.0-openjdk katello libvirt')

    run('setenforce 0')
    run('katello-installer -v -d --foreman-admin-password="{0}"'.format(
        admin_password))
    run('service iptables stop')

    if distro.startswith('rhel7'):
        run('service firewalld stop')

    # Ensure that the installer worked
    run('hammer -u admin -p {0} ping'.format(admin_password))


def reservation_install_nightly(admin_password=None):
    """Task to execute reservation, setup_ddns and install_nightly

    The ``admin_password`` parameter will be passed to the install_nightly
    task.

    """
    execute(reservation)
    execute(setup_ddns, env['vm_domain'], env['vm_ip'], host=env['vm_ip'])
    execute(install_nightly, admin_password, host=env['vm_ip'])


def partition_disk():
    """Re-partitions disk to increase the size of /root to handle
    synchronization of larger repositories.

    """
    run('umount /home')
    run('lvremove /dev/mapper/*home')
    run('lvresize -l +100%FREE /dev/mapper/*root')
    run('if uname -r | grep -q el6; then resize2fs /; else xfs_growfs /; fi')
