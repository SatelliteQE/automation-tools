import os
import time

from fabric.api import execute, put, run
from StringIO import StringIO


def setup_ddns(entry_domain, entry_hash, host_ip):
    """Task to setup DDNS client

    :param str entry_domain: the FQDN of the host
    :param str entry_hash: host FQDN DDNS entry hash
    :param str host_ip: host IP address

    """
    ddns_package_url = os.environ.get('DDNS_PACKAGE_URL')
    target, domain = entry_domain.split('.', 1)

    run('yum install -y {}'.format(ddns_package_url))
    run('echo "{} {} {}" >> /etc/redhat-ddns/hosts'.format(
        target, domain, entry_hash))
    run('echo "127.0.0.1 {} localhost" > /etc/hosts'.format(entry_domain))
    run('echo "{} {}" >> /etc/hosts'.format(
        host_ip, domain))
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


def reservation():
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

    """
    options = {
        'vm_ram': os.environ.get('VM_RAM'),
        'vm_cpu': os.environ.get('VM_CPU'),
        'vm_domain': os.environ.get('VM_DOMAIN'),
        'ddns_hash': os.environ.get('DDNS_HASH'),
        'source_image': os.environ.get('SOURCE_IMAGE'),
        'target_image': os.environ.get('TARGET_IMAGE'),
    }

    run('snap-guest -b {source_image} -t {target_image} -m {vm_ram} '
        '-c {vm_cpu} -d {vm_domain} -n bridge=br0 -f'.format(**options))

    # Give some time to machine boot
    time.sleep(60)

    result = run('ping -c 1 {}.local'.format(
        options['target_image']))
    vm_ip = result.split('(')[1].split(')')[0]

    domain = '{target_image}.{vm_domain}'.format(**options)

    execute(setup_ddns, domain, options['ddns_hash'], vm_ip, host=vm_ip)
