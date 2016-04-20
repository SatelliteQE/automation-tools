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
        return '{0}@{1}:{2}'.format(self.user, self.hostname, self.port)


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
    """Get oauth_consumer_key, oauth_consumer_secret and pulp_oauth_secret
    information.

    :return: Tuple containing (oauth_consumer_key, oauth_consumer_secret,
        pulp_oauth_secret)
    """
    result = run('grep oauth_consumer /etc/foreman/settings.yaml', quiet=True)
    for line in result.splitlines():
        if 'oauth_consumer_key' in line:
            oauth_consumer_key = line.split(': ')[1].strip()
        if 'oauth_consumer_secret' in line:
            oauth_consumer_secret = line.split(': ')[1].strip()
    result = run('grep "^oauth_secret" /etc/pulp/server.conf', quiet=True)
    pulp_oauth_secret = result.split(': ')[1].strip()
    print(
        'oauth_consumer_key: {0}\n'
        'oauth_consumer_secret: {1}\n'
        'pulp_oauth_secret: {2}'
        .format(oauth_consumer_key, oauth_consumer_secret, pulp_oauth_secret)
    )
    return (oauth_consumer_key, oauth_consumer_secret, pulp_oauth_secret)


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
    cert_path = '{0}-certs.tar'.format(capsule_hostname)
    result = run('[ -f {0} ]'.format(cert_path), quiet=True)
    if result.failed or force:
        run('capsule-certs-generate -v --capsule-fqdn {0} '
            '--certs-tar {1}'.format(capsule_hostname, cert_path))
    return cert_path


@task
def register_capsule():
    """Register the capsule on the Satellite 6 server."""
    config = _get_config()
    run(
        'yum -y localinstall '
        'http://{0}/pub/katello-ca-consumer-latest.noarch.rpm'
        .format(config.server.hostname),
        warn_only=True
    )
    if config.activation_key:
        run(
            'subscription-manager register '
            '--org={0} --activationkey={1} --force'
            .format(config.organization_label, config.activation_key)
        )
    elif config.content_view:
        run(
            'subscription-manager register --username {0} --auto-attach '
            '--force --password {1} --org {2} --environment {3} '
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
        capsule_fqdn, cert_path, oauth_consumer_key,
        oauth_consumer_secret, pulp_oauth_secret):
    """Install and run capsule-installer."""
    config = _get_config()
    run('yum -y install satellite-capsule')
    run(
        'foreman-installer -v --scenario capsule '
        '--certs-tar {cert_path} '
        '--foreman-base-url "https://{parent_fqdn}" '
        '--oauth-consumer-key "{oauth_consumer_key}" '
        '--oauth-consumer-secret "{oauth_consumer_secret}" '
        '--parent-fqdn "{parent_fqdn}" '
        '--pulp-oauth-secret "{pulp_oauth_secret}" '
        '--register-in-foreman true '
        '--trusted-hosts "{capsule_fqdn}" '
        '--trusted-hosts "{parent_fqdn}"'
        .format(
            capsule_fqdn=capsule_fqdn,
            cert_path=cert_path,
            oauth_consumer_key=oauth_consumer_key,
            oauth_consumer_secret=oauth_consumer_secret,
            parent_fqdn=config.server.hostname,
            pulp_oauth_secret=pulp_oauth_secret,
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
        'hammer --username {0} --password {1} --output json {2}'
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
        'capsule content available-lifecycle-environments --id {0}'
        .format(capsule_id),
    )


@task
def hammer_capsule_add_lcenv(capsule_id, lcenv_id):
    """Add the lifecycle environment to the capsule.

    :param capsule_id: The capsule ID to add the lifecycle environment.
    :param lcenv_id: The lifecycle environment ID to add to the capsule.
    """
    return hammer(
        'capsule content add-lifecycle-environment '
        '--environment-id {0} --id {1}'
        .format(lcenv_id, capsule_id)
    )


@task
def hammer_product_create(name, organization_id):
    """Create a product

    :param name: name of the product
    :param organization_id: organization where the product will be created
    """
    return hammer(
        'product create --name "{0}" --organization-id "{1}"'
        .format(name, organization_id)
    )


@task
def hammer_repository_create(name, organization_id, product_name, url):
    """Create a repository

    :param name: name of the repository
    :param organization_id: organization where the repository will be created
    :param product_name: name of the product which the repository belongs
    :param url: repository source URL
    """
    return hammer(
        'repository create --name "{0}" '
        '--content-type "yum" '
        '--organization-id "{1}" '
        '--product "{2}" '
        '--url "{3}"'
        .format(name, organization_id, product_name, url)
    )


@task
def hammer_repository_synchronize(name, organization_id, product_name):
    """Synchronize a repository

    :param name: name of the repository to synchronize
    :param organization_id: organization_id where the repository was created
    :param product_name: product name which the repository belongs
    """
    return hammer(
        'repository synchronize --name "{0}" '
        '--organization-id "{1}" '
        '--product "{2}"'
        .format(name, organization_id, product_name)
    )


@task
def hammer_content_view_create(name, organization_id):
    """Create a content view

    :param name: name of the content view
    :param organization_id: organization where the content view will be created
    """
    return hammer(
        'content-view create --name "{0}" --organization-id "{1}"'
        .format(name, organization_id)
    )


@task
def hammer_content_view_add_repository(
        name, organization_id, product_name, repository_name):
    """Add a repository to a content view

    :param name: name of the content view which the repository will be added
    :param organization_id: organization where the content view, product and
        repository were created
    :param product_name: name of the product where the repository was created
    :param repository_name: repository name which will be added to the content
        view
    """
    return hammer(
        'content-view add-repository --name "{0}" '
        '--organization-id "{1}" '
        '--product "{2}" '
        '--repository "{3}"'
        .format(name, organization_id, product_name, repository_name)
    )


@task
def hammer_content_view_publish(name, organization_id):
    """Publish a content view

    :param name: name of the content view which will be published
    :param organization_id: organization where the content view was created
    """
    return hammer(
        'content-view publish --name "{0}" --organization-id "{1}"'
        .format(name, organization_id)
    )


@task
def hammer_activation_key_create(
        name, organization_id, content_view_name,
        lifecycle_environment_name='Library'):
    """Create an activation key

    :param name: name of the acktivation key which will be created
    :param organization_id: organization where the activation key will be
        created
    :param content_view_name: content view name which will be linked to the
        activation key
    :param lifecycle_environment_name: lifecycle environment name which will be
        linked to the activation key
    """
    return hammer(
        'activation-key create --name "{0}" '
        '--content-view "{1}" '
        '--lifecycle-environment "{2}" '
        '--organization-id "{3}"'
        .format(
            name,
            content_view_name,
            lifecycle_environment_name,
            organization_id
        )
    )


@task
def hammer_activation_key_add_subscription(
        name, organization_id, subscription_id):
    """Add a subscription to an activation key

    :param name: name of the activation key which the subscription will be
        added
    :param organization_id: organization where the activation key was created
    :param subscription_id: subscription which will be added to the activation
        key
    """
    return hammer(
        'activation-key add-subscription --name "{0}" '
        '--organization-id "{1}" '
        '--subscription-id "{2}"'
        .format(name, organization_id, subscription_id)
    )


@task
def setup_capsule_content(
        activation_key_name,
        content_view_name,
        organization_id,
        product_name,
        rhel_repo_name,
        rhel_repo_url,
        satellite_capsule_repo_name,
        satellite_capsule_repo_url,
        satellite_tools_repo_name,
        satellite_tools_repo_url):
    """Setup the content used to provision a capsule.


    :param activation_key_name: name of the activation key which will be
        created
    :param content_view_name: name of the content view which will be created
    :param organization_id: organization where all entities will be created
    :param product_name: name of the product which will be created
    :param rhel_repo_name: name of the RHEL repository which will be created
    :param rhel_repo_url: URL of the RHEL repository which will be created
    :param satellite_capsule_repo_name: name of the capsule repository which
        will be created
    :param satellite_capsule_repo_url: URL of the capsule repository which will
        be created
    :param satellite_tools_repo_name: name of the satellite tools repository
        which will be created
    :param satellite_tools_repo_url: URL of the satellite tools repository
        which will be created
    """
    hammer_product_create(product_name, organization_id)
    hammer_repository_create(
        rhel_repo_name, organization_id, product_name, rhel_repo_url)
    hammer_repository_create(
        satellite_capsule_repo_name,
        organization_id,
        product_name,
        satellite_capsule_repo_url
    )
    hammer_repository_create(
        satellite_tools_repo_name,
        organization_id,
        product_name,
        satellite_tools_repo_url
    )
    hammer_repository_synchronize(
        rhel_repo_name, organization_id, product_name)
    hammer_repository_synchronize(
        satellite_capsule_repo_name, organization_id, product_name)
    hammer_repository_synchronize(
        satellite_tools_repo_name, organization_id, product_name)
    hammer_content_view_create(
        content_view_name, organization_id)
    hammer_content_view_add_repository(
        content_view_name, organization_id, product_name, rhel_repo_name)
    hammer_content_view_add_repository(
        content_view_name,
        organization_id,
        product_name,
        satellite_capsule_repo_name
    )
    hammer_content_view_add_repository(
        content_view_name,
        organization_id,
        product_name,
        satellite_tools_repo_name
    )
    hammer_content_view_publish(content_view_name, organization_id)
    product_id = run(
        "hammer --csv subscription list --organization-id='{0}' "
        "--search='name=\"{1}\"' | awk -F, 'NR>1{{print$8}}'"
        .format(organization_id, product_name),
        quiet=True
    )
    hammer_activation_key_create(
        activation_key_name, organization_id, content_view_name)
    hammer_activation_key_add_subscription(
        activation_key_name, organization_id, product_id)


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
    if capsule['id'] == 1:
        print('Skipping default capsule...')
        return
    lcenvs = hammer_capsule_lcenvs(capsule['id'])
    for lcenv in lcenvs:
        hammer_capsule_add_lcenv(capsule['id'], lcenv['id'])
    hammer(
        'capsule content synchronize --async --id {0}'.format(capsule['id'])
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
            capsule_installer(capsule.hostname, cert_path, *oauth_info)
