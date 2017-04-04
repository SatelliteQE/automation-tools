"""A set of common tasks for automating interactions with Satellite & Capsule.

Many commands are affected by environment variables. Unless stated otherwise,
all environment variables are required.
"""
import logging
import os
import subprocess
import time

from fabric.api import execute, run


HIGHLIGHT_LEVEL_NUM = 25
logging.addLevelName(HIGHLIGHT_LEVEL_NUM, 'HIGHLIGHT')


class MyLogger(logging.Logger):
    """New Logger class to add new logger level"""
    def highlight(self, message, *args, **kws):
        """New custom Logger level name highlight

        Created to highlight the main events in logging
        """
        self.log(HIGHLIGHT_LEVEL_NUM, message, *args, **kws)


class SingleLevelClassFilter(logging.Filter):
    """New Logging level class filter"""
    def __init__(self, level, reject):
        """
        :param int level: The level number to filter out
        :param bool reject: Filters if set to False and doesnt filters if True
        """
        self.level = level
        self.reject = reject

    def filter(self, record):
        if self.reject:
            return (record.levelno != self.level)
        else:
            return (record.levelno == self.level)


def logger():
    """Logger to log messages to Console and to files

    This logger creates two files:
    full_upgrade: Contents all logging level logs
    upgrade_highlights: Contents only Highlight logging level logs

    These highlight level logs have been used as contents of Upgrade status
    email sent via jenkins

    :returns object log: Logger object to log different logging levels
    """
    logging.setLoggerClass(MyLogger)
    log = logging.getLogger('upgrade_logging')
    paramiko_logger = logging.getLogger("paramiko.transport")
    paramiko_logger.disabled = True
    if not log.handlers:
        # Log files
        logfile_path = os.path.abspath('full_upgrade')
        highlight_path = os.path.abspath('upgrade_highlights')
        # Hamdlers
        hdlr = logging.FileHandler(logfile_path)
        hdlr2 = logging.FileHandler(highlight_path)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        ch = logging.StreamHandler()
        # Filters
        f1 = SingleLevelClassFilter(HIGHLIGHT_LEVEL_NUM, False)
        hdlr2.addFilter(f1)
        # Add Handlers
        log.addHandler(hdlr)
        log.addHandler(hdlr2)
        log.addHandler(ch)
        # Set Level
        log.setLevel(logging.INFO)
    return log


log = logger()


def reboot(halt_time=300):
    """Reboots the host.

    Also halts the execution until reboots according to given time.

    :param int halt_time: Halt execution in seconds.
    """
    halt_time = halt_time
    log.info('Rebooting the host, please wait .... ')
    try:
        run('reboot', warn_only=True)
    except:
        pass
    time.sleep(halt_time)


def copy_ssh_key(from_host, to_hosts):
    """This will generate(if not already) ssh-key on from_host
    and copy that ssh-key to to_hosts.

    Beware that to and from hosts should have authorized key added
    for test-running host.

    :param string from_host: Hostname on which the key to be generated and
        to be copied from.
    :param list to_hosts: Hostnames on to which the ssh-key will be copied.

    """
    execute(lambda: run('mkdir -p ~/.ssh'), host=from_host)
    # do we have privkey? generate only pubkey
    execute(lambda: run(
        '[ ! -f ~/.ssh/id_rsa ] || '
        'ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub'), host=from_host)
    # dont we have still pubkey? generate keypair
    execute(lambda: run(
        '[ -f ~/.ssh/id_rsa.pub ] || '
        'ssh-keygen -f ~/.ssh/id_rsa -t rsa -N \'\''), host=from_host)
    # read pubkey content in sanitized way
    pub_key = execute(lambda: run(
        '[ ! -f ~/.ssh/id_rsa.pub ] || cat ~/.ssh/id_rsa.pub'),
        host=from_host)[from_host]
    if pub_key:
        for to_host in to_hosts:
            execute(lambda: run('mkdir -p ~/.ssh'), host=to_host)
            # deploy pubkey to another host
            execute(lambda: run(
                'echo "{0}" >> ~/.ssh/authorized_keys'.format(pub_key)
            ), host=to_host)


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
        if time.time() > timeup:
            log.warning('The timout for pinging the host {0} has '
                        'reached!'.format(host))
            return False
        if int(output.split()[-1]) == 0:
            return True
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
            log.warning(
                'The timeout for getting the Hostname from IP has reached!')
            return False
        try:
            output = execute(lambda: run('hostname'), host=ip)
            log.info('Hostname determined as: {0}'.format(output[ip]))
            break
        except:
            time.sleep(5)
    return output[ip]
