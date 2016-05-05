"""A set of common tasks for automating interactions with Satellite & Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import subprocess
import sys
import time
from fabric.api import execute, run


def reboot(halt_time=300):
    """Reboots the host.

    Also halts the execution until reboots according to given time.

    :param int halt_time: Halt execution in seconds.
    """
    halt_time = halt_time
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
    if int(execute(lambda: run('[ -f ~/.ssh/id_rsa.pub ]; echo $?'),
                   host=from_host)[from_host]) == 0:
        pub_key = execute(lambda: run(
            'cat ~/.ssh/id_rsa.pub'), host=from_host)[from_host]
        execute(lambda: run('[ ! -f ~/.ssh/authorized_keys ] && '
                            'touch ~/.ssh/authorized_keys',
                            warn_only=True), host=to_host)
        execute(lambda: run(
            'echo "{0}" >> ~/.ssh/authorized_keys'.format(pub_key)),
            host=to_host)


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
            print('SUCCESS !! The given host {0} has been pinged!!'.format(
                host))
            break
        elif time.time() > timeup:
            print('The timout for pinging the host {0} has reached!'.format(
                host))
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
