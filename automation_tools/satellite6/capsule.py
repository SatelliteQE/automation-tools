"""Tasks for helping automating the provisioning of Satellite 6 Capsules"""
from __future__ import print_function
import json

from fabric.api import env, get, put, run, settings, task
from fabric.operations import _AttributeList


class _AttributeDict(dict):
    """Simple dict subclass to allow arbitrary attibute access"""


class ImproperlyConfigured(Exception):
    """Indicates that the capsule configuration is somehow improperly
    configured
    - for example, if the configuration is not loaded or some required
    configuration is missing.

    """


class Credentials(object):
    """Stores a server SSH credentials information.

    Usage::

        cred1 = Credentials('admin', 'password')
        cred2 = Credentials(key_filename='/path/to/ssh.key')

    """
    def __init__(self, user=None, password=None, key_filename=None):
        self.user = user
        self.password = password
        self.key_filename = key_filename


class HostConfig(Credentials):
    """Stores a host's hostname and credentials information.

    Usage::

        cred1 = HostConfig('host1.example.com', 'admin', 'password')
        cred2 = HostConfig(
            'host2.example.com', key_filename='/path/to/ssh.key')

    """
    def __init__(self, hostname=None, port=22, *args, **kwargs):
        super(HostConfig, self).__init__(*args, **kwargs)
        self.hostname = hostname
        self.port = port

    @property
    def host_string(self):
        """Return a host_string in the format expected by Fabric"""
        return '{}@{}:{}'.format(self.user, self.hostname, self.port)


class Config(object):
    """Configuration information provide easy access to configuration and some
    helper methods to identify if some configuration is present or not.

    """
    def __init__(self, path):
        self.path = path
        self.organization_label = None
        self.environment = None
        self.content_view = None
        self.activation_key = None
        self.admin_user = None
        self.admin_password = None
        self.defaults = None
        self.server = None
        self.capsules = []
        self._key_filenames = set()

        self._parse()

    def _parse(self):
        """Parse the configuration and store the contents"""
        with open(self.path) as handler:
            data = json.load(handler)
        self.organization_label = data.get('organization-label')
        self.environment = data.get('environment')
        self.content_view = data.get('content-view')
        self.activation_key = data.get('activation-key')
        self.admin_user = data.get('admin-user')
        self.admin_password = data.get('admin-password')
        defaults = data.get('defaults')
        if defaults is not None and isinstance(defaults, dict):
            key_filename = defaults.get('key-filename')
            self._key_filenames.add(key_filename)
            self.defaults = Credentials(
                user=defaults.get('user'),
                password=defaults.get('password'),
                key_filename=key_filename,
            )
        server = data.get('server')
        if server is not None and isinstance(server, dict):
            key_filename = server.get('key-filename')
            self._key_filenames.add(key_filename)
            self.server = HostConfig(
                hostname=server.get('hostname'),
                user=server.get('user', self.defaults.user),
                password=server.get('password', self.defaults.password),
                key_filename=key_filename,
            )
        capsules = data.get('capsules')
        if capsules is not None and isinstance(capsules, list):
            for capsule in capsules:
                if capsule is not None and isinstance(capsule, dict):
                    key_filename = capsule.get('key-filename')
                    self._key_filenames.add(key_filename)
                    self.capsules.append(HostConfig(
                        hostname=capsule.get('hostname'),
                        user=capsule.get('user', self.defaults.user),
                        password=capsule.get(
                            'password', self.defaults.password),
                        key_filename=key_filename,
                    ))

    @property
    def key_filenames(self):
        """Return a list of collect key filenames or None if the list is
        empty.

        """
        if self._key_filenames:
            return list(self._key_filenames)
        else:
            return None

    @property
    def passwords(self):
        """Return a dict in the format suited for Fabric usage in order to
        define passwords for hosts.

        """
        passwords = {}
        if self.server.password and not self.server.key_filename:
            passwords[self.server.host_string] = self.server.password
        for capsule in self.capsules:
            if capsule.password and not capsule.key_filename:
                passwords[capsule.host_string] = capsule.password
        return passwords


def _get_config():
    """Get the capsule configuration if available in the fabric environment
    else raise ``ImproperlyConfigured``.

    """
    config = env.get('capsule_config')
    if config is None:
        raise ImproperlyConfigured(
            'Make sure to run load_capsule_config task.')
    return config


def _lower_dict_keys(d):
    """Helper for ensuring that all dictionary keys are lowercase."""
    if isinstance(d, list):
        return [_lower_dict_keys(v) for v in d]
    elif isinstance(d, dict):
        return dict((k.lower(), _lower_dict_keys(v)) for k, v in d.iteritems())
    else:
        return d


@task
def load_capsule_config(path):
    env['capsule_config'] = Config(path)


@task
def get_oauth_info():
    """Get foreman_oauth_key, foreman_oauth_secret and pulp_oauth_secret
    information.

    :return: Tuple containing (foreman_oauth_key, foreman_oauth_secret,
        pulp_oauth_secret)

    """
    result = run('grep oauth_consumer /etc/foreman/settings.yaml', quiet=True)
    for line in result.splitlines():
        if 'oauth_consumer_key' in line:
            foreman_oauth_key = line.split(': ')[1].strip()
        if 'oauth_consumer_secret' in line:
            foreman_oauth_secret = line.split(': ')[1].strip()
    result = run('grep "^oauth_secret" /etc/pulp/server.conf', quiet=True)
    pulp_oauth_secret = result.split(': ')[1].strip()
    print(
        'foreman_oauth_key: {}\nforeman_oauth_secret: {}\n'
        'pulp_oauth_secret: {}'
        .format(foreman_oauth_key, foreman_oauth_secret, pulp_oauth_secret)
    )
    return (foreman_oauth_key, foreman_oauth_secret, pulp_oauth_secret)


@task
def generate_capsule_certs(capsule_hostname, force=False):
    """Generate certificates for a capsule.

    Run ``capsule-certs-generate --capsule-fqdn <capsule_hostname> --certs-tar
    "<capsule_hostname>-certs.tar"`` in order to generate them.

    The resulting tarbal will be store on the working directory of the remote
    host.

    :param str capsule_hostname: The fully qualified domain name for the
        capsule.
    :param bool force: Force creation of the capsule cert even if it is
        already created.

    """
    cert_path = '{}-certs.tar'.format(capsule_hostname)
    result = run('[ -f {} ]'.format(cert_path), quiet=True)
    if result.failed or force:
        run('capsule-certs-generate -v --capsule-fqdn {} '
            '--certs-tar {}'.format(capsule_hostname, cert_path))
    return cert_path


@task
def register_capsule():
    """Register the capsule on the Satellite 6 server."""
    config = _get_config()
    run(
        'rpm -Uvh http://{}/pub/katello-ca-consumer-latest.noarch.rpm'
        .format(config.server.hostname),
        warn_only=True
    )
    if config.activation_key:
        run(
            'subscription-manager register --org={} --activationkey={} --force'
            .format(config.organization_label, config.activation_key)
        )
    elif config.content_view:
        run(
            'subscription-manager register --username {} --auto-attach '
            '--force --password {} --org {} --environment {} '
            .format(
                config.admin_user,
                config.admin_password,
                config.organization_label,
                config.content_view,
            )
        )
    else:
        raise ImproperlyConfigured(
            'An activation key or content_view name is required.')
    run('yum repolist')


@task
def capsule_installer(
        foreman_oauth_key, foreman_oauth_secret, pulp_oauth_secret):
    """Install and run capsule-installer."""
    config = _get_config()
    run('yum -y install capsule-installer')
    run(
        'capsule-installer -v --certs-tar *-certs.tar --parent-fqdn {} '
        '--pulp true --pulp-oauth-secret {} --puppet true --puppetca true '
        '--foreman-oauth-secret {} --foreman-oauth-key {} '
        '--register-in-foreman true --qpid-router true --reverse-proxy true'
        .format(
            config.server.hostname,
            pulp_oauth_secret,
            foreman_oauth_secret,
            foreman_oauth_key
        )
    )


@task
def hammer(command):
    """Run hammer -u <admin_user> -p <admin_password> --output json <command>.

    :param str command: The hammer subcommand to run.
    :return: Return a JSON decoded object containing the result of the command.
        The returned object will exhibit ``failed`` and ``succeeded`` boolean
        attributes specifying whether the command failed or succeeded, and will
        also include the return code as the ``return_code`` attribute.

    """
    config = _get_config()
    command_result = run(
        'hammer --username {} --password {} --output json {}'
        .format(config.admin_user, config.admin_password, command),
        quiet=True
    )
    result = _lower_dict_keys(json.loads(command_result))
    print(result)
    if isinstance(result, list):
        result = _AttributeList(result)
    elif isinstance(result, dict):
        result = _AttributeDict(result)
    result.succeeded = command_result.succeeded
    result.failed = command_result.failed
    result.return_code = command_result.return_code
    return result


@task
def hammer_capsule_lcenvs(capsule_id):
    """Get the available lifecycle environments of a capsule.

    :param capsule_id: The capsule ID to get the availables lifecycle
        environments.
    :returns: A list of lifecycle environment dictonaries. For example:
        ``[{u'organization': u'Default Organization', u'id': 1,
        u'name': u'Library'}]``.
    :rtype: list

    """
    return hammer(
        'capsule content available-lifecycle-environments --id {}'
        .format(capsule_id),
    )


@task
def hammer_capsule_add_lcenv(capsule_id, lcenv_id):
    """Add the lifecycle environment to the capsule.

    :param capsule_id: The capsule ID to add the lifecycle environment.
    :param lcenv_id: The lifecycle environment ID to add to the capsule.

    """
    return hammer(
        'capsule content add-lifecycle-environment --environment-id {} --id {}'
        .format(lcenv_id, capsule_id)
    )


@task
def hammer_capsule_list():
    """Get the list of all Satellite capsules.

    :returns: A list of (capsule_id, capsule_name) tuples. For example:
        ``[{u'url': u'https://capsule1.example.com:9090', u'id': 1,
        u'name': u'capsule1.example.com'}]``.
    :rtype: list

    """
    return hammer('capsule list')


def sync_capsule_content(capsule):
    """Start content synchronization in the capsule. The content
    synchronization will be asynchronously, check the capsule logs to see when
    it have finished.

    :param dict capsule: A capsule dictionary containing its ``id`` and
        ``name``.

    """
    if capsule['id'] != 1:
        print('Skipping default capsule...')
        return
    lcenvs = hammer_capsule_lcenvs(capsule['id'])
    for lcenv in lcenvs:
        hammer_capsule_add_lcenv(capsule['id'], lcenv['id'])
    hammer(
        'capsule content synchronize --async --id {}'.format(capsule['id'])
    )


@task
def setup_capsules(path):
    """Reads the configuration, create capsules and start content sync on
    them.

    """
    load_capsule_config(path)
    config = env.capsule_config
    server = config.server.host_string

    # Let Fabric know how to log into the hosts
    env.passwords = config.passwords
    env.key_filename = config.key_filenames

    # The oauth information is needed for every capsule register. Cache this
    # information.
    with settings(host_string=server):
        oauth_info = get_oauth_info()

    # Register each capsule on the server
    for capsule in config.capsules:
        with settings(host_string=server):
            cert_path = generate_capsule_certs(capsule.hostname)
            get(remote_path=cert_path, local_path=cert_path)

        with settings(host_string=capsule.host_string):
            register_capsule()
            put(local_path=cert_path)
            capsule_installer(*oauth_info)

    # Start content synchronization in all registered capsules
    with settings(host_string=server):
        for capsule in hammer_capsule_list():
            sync_capsule_content(capsule)
