"""Utilities tasks and functions"""
from __future__ import print_function

import os
import re
import sys
import subprocess
import time

from bs4 import BeautifulSoup
from fabric.api import env, run, warn_only

from six.moves.urllib.request import urlopen


def distro_info():
    """Task which figures out the distro information based on the
    /etc/redhat-release file

    A ``(distro, major_version)`` tuple is returned if called as a function.
    For RHEL X.Y.Z it will return ``('rhel', X)``. For Fedora X it will return
    ``('fedora', X)``. Be aware that the major_version is an integer.

    """
    # Create/manage host cache
    cache = env.get('distro_info_cache')
    host = env['host']
    if cache is None:
        cache = env['distro_info_cache'] = {}

    if host not in cache:
        # Grab the information and store on cache
        release_info = run('cat /etc/redhat-release', quiet=True)
        if release_info.failed:
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
        match = re.search(r' ([0-9.]+) ', release_info)
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


def run_command(cmd=None):
    """ Task to run only sane commands
    :param str cmd: command to be run

    """
    if cmd:
        run(cmd)


def get_discovery_image():
    """ Task for getting unattended foreman-discovery ISO image
    :return: foreman-discovery-image iso under /var/lib/libvirt/images/
    """
    url = os.environ.get('BASE_URL') + '/Packages/'
    soup = BeautifulSoup(urlopen(url).read())
    for link in soup.findAll('a'):
        if 'foreman-discovery-image' in link.string:
            discovery_image = link.string
    try:
        run("wget -O /tmp/" + discovery_image + " " + url + discovery_image)
        run('cd /tmp/ ; rpm2cpio ' + discovery_image + '|cpio -idmv')
        run('cp /tmp/usr/share/foreman-discovery-image/'
            + discovery_image.split('.el')[0] + '.iso /tmp/')
        run('cp /tmp/usr/bin/discovery-remaster /tmp/')
        run('/tmp/discovery-remaster /tmp/' + discovery_image.split('.el')[0]
            + '.iso "fdi.pxgw=' + os.environ.get('GATEWAY') +
            ' fdi.pxdns=$(cat /etc/resolv.conf|grep -i "^nameserver"|'
            'head -n1|cut -d " " -f2) proxy.url=https://'
            + os.environ.get('IPADDR') +
            ':9090 proxy.type=proxy fdi.pxfactname1=myfact '
            'fdi.pxfactvalue1=somevalue fdi.pxauto=1" /var/lib/libvirt/images/'
            + os.environ.get('DISCOVERY_ISO'))
        size = run('du -h "/var/lib/libvirt/images/"' +
                   os.environ.get('DISCOVERY_ISO')
                   + ' | cut -f1 | tr -d [:alpha:]')
        if int(size) < 150:
            raise Exception("Generated ISO size is less than 150M!"
                            " Check if ISO is corrupted.")
    finally:
        run('rm /tmp/foreman-discovery-image* /tmp/discovery-remaster '
            '/tmp/usr -rvf')


def get_packages_name(html):
    soup = BeautifulSoup(html)
    anchors = soup.findAll('a')
    links = []
    for a in anchors:
        links.append(a['href'])
    links = filter(lambda k: 'rpm' in k, links)
    return links


def get_packages(url, package_name):
    run('wget -P packages/ ' + url + package_name)


def compare_builds(url1, url2):
    """ Task to to compare packages in two different release engineering builds
     and verify rpm signature.
    :return: Check Package Versions in both builds are same and all packages
     under RCM_COMPOSE_URL are signed!
    """
    signature = os.getenv('SIGNATURE')
    flag = flag1 = flag2 = 0
    list1 = get_packages_name(urlopen(url1).read())
    list1.sort()
    list2 = get_packages_name(urlopen(url2).read())
    list2.sort()
    with warn_only():
        try:
            run('mkdir packages')
            for pkg in range(len(list2)):
                get_packages(url2, list2[pkg])
            for pkg in range(len(list2)):
                if 'NOT OK' not in run('rpm -K packages/' + list1[pkg]):
                    flag1 = flag1 + 1
                    if signature in run(
                                            'rpm -qpi packages/' +
                                            list2[pkg] + '| grep "Signature" '
                    ):
                        flag2 = flag2 + 1
                    else:
                        print('signature ' + signature + ' not matched for '
                              + list2[pkg])
                else:
                    print(list2[pkg] + 'package is not signed')
        finally:
            run('rm packages -rf')

    print("========================= Overall Report ======================")

    print(
        "There are " + str(len(list1)) + " packages in " + url1 + " and "
        + str(len(list2)) + " packages in " + url2
    )

    for pkg in range(len(list1)):
        if list1[pkg] == list2[pkg]:
            flag = flag + 1
        else:
            print(
                "The version of package " + list1[pkg] +
                " from build1 is not similar to version of package " + list2[
                    pkg]
                + " from build2."
            )

    if flag == len(list1) - 1:
        print("Versions in both builds are same")
    else:
        print(str((len(list1)) - flag) + " packages version found mismatched!")

    if flag1 == len(list1):
        print("All packages are signed!")
    else:
        print(str(len(list1) - flag1) + 'packages are not signed!!')

    if flag2 == len(list1):
        print("Signature matched for all packages!!")
    else:
        print('Signature ' + signature + ' for ' + str(len(list1) - flag2) +
              ' packages not matched!!')
    print("================================================================")


def host_cmd_check(cmd, timeout=7):
    """Helper to run commands and poll until returncode 0 or timeout
    :param cmd: A string. The cmd you want to poll for.
    :param int timeout: The polling timeout in minutes.
    """
    timeup = time.time() + int(timeout) * 60
    while True:
        command = subprocess.Popen(
            '{0}'.format(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        output = command.communicate()
        print(output)
        # Checking the return code of ping is 0
        if time.time() > timeup:
            print('Running {0} timed out for host '.format(cmd))
            return False
        if command.returncode == 0:
            return True, output
        else:
            time.sleep(5)


def host_ssh_availability_check(host):
    """This ensures the given host has ssh up and running..
    :param host: A string. The IP or hostname of host.
    """
    _, ip = host_pings(host)
    print('Checking SSH availability')
    _, output = host_cmd_check('nc -vn {0} 22 <<< \'\''.format(ip))
    return output


def host_pings(host):
    """This ensures the given IP/hostname pings succesfully.
    :param host: A string. The IP or hostname of host.
    """
    _, output = host_cmd_check('ping -c1 {0}; echo $?'.format(host))
    output = str(output[0])
    ip = output[output.find("(") + 1:output.find(")")]
    status, _ = host_cmd_check('ping -c1 {0} | '
                               'grep \'1 received\''.format(host))
    return status, ip
