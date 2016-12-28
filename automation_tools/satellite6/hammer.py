"""Tasks for helping to execute hammer commands on satellite"""
from fabric.api import env, run, task
import json


class _AttributeDict(dict):
    """Simple dict subclass to allow arbitrary attibute access"""
    pass


class _AttributeList(list):
    """Simple List subclass to allow arbitrary attribute access."""
    pass


class ImproperlyConfigured(Exception):
    """Indicates that the Hammer configuration is improperly configured
    - for example, hammer configuration is not set or missing.
    """


def _lower_dict_keys(d):
    """Helper for ensuring that all dictionary keys are lowercase."""
    if isinstance(d, list):
        return [_lower_dict_keys(v) for v in d]
    elif isinstance(d, dict):
        return dict((k.lower(), _lower_dict_keys(v)) for k, v in d.iteritems())
    else:
        return d


def get_attribute_value(hammer_result, search_key, attribute):
    """Gets the attribute value from hammer_reult using the search key

    e.g. Run hammer() def for 'capsule list' and get hammer_result then
    search capsules 'id' attribute by 'capsule name' search key.

    :param list/dict hammer_result: hammer result from hammer() defination
    :param str attribute: The attribute name of which value to be fetched
    :param str search_key: The search_key whose attribute to be fetched
    :return Returns a string/list/dict as attribute value
    """
    if isinstance(hammer_result, list):
        key_index = None
        for i in range(len(hammer_result)):
            if search_key in hammer_result[i].values():
                key_index = i
                break
        else:
            raise KeyError(
                'Unable to find search_key {} in given hammer '
                'result to get attribute value'.format(search_key))
        return hammer_result[key_index][attribute]
    elif isinstance(hammer_result, dict):
        if search_key not in hammer_result.values():
            raise KeyError(
                'Unable to find search_key {} in given hammer '
                'result to get attribute value'.format(search_key))
        return hammer_result[attribute]
    else:
        raise TypeError('hammer data is not one of type list/dict.')


def set_hammer_config(user=None, password=None):
    """Sets the hammer admin username and password fabric env. variables to run
    hammer commands"""
    env['hammer_user'] = 'admin' if not user else user
    env['hammer_password'] = 'changeme' if not password else password


@task
def hammer(command):
    """Run hammer -u <admin_user> -p <admin_password> --output json <command>.

    This method has a dependency on set_hammer_config function.

    :param str command: The hammer subcommand to run.
    :return: Return a JSON decoded object containing the result of the command.
        The returned object will exhibit ``failed`` and ``succeeded`` boolean
        attributes specifying whether the command failed or succeeded, and will
        also include the return code as the ``return_code`` attribute.
    """
    command_result = run(
        'hammer --username {0} --password {1} --output json {2}'
        .format(env.get('hammer_user'), env.get('hammer_password'), command),
        quiet=True
    )
    try:
        data = json.loads(command_result)
    except ValueError:
        data = command_result
    result = _lower_dict_keys(data)
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
def hammer_repository_set_enable(name, product, organization_id, arch):
    """Enables a Redhat Repository

    :param name: Name of the repository
    :param product: Name of the Product where repository is listed
    :param organization_id: Organization where the repository will be enabled
    :param arch: The architecture x86_64 or i386 or ia64
    """
    return hammer(
        'repository-set enable --name "{0}" '
        '--product "{1}" '
        '--organization-id {2} '
        '--basearch "{3}"'.format(
            name, product, organization_id, arch)
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
def hammer_content_view_promote_version(
        cv_name, cv_ver_id, lc_env_id, organization_id):
    """Promotes a content view version

    :param cv_name: name of the content view which will be published
    :param cv_ver_id: CV Version id to be promoted
    :param lc_env_id: LC Environment id onto which cv version to be promoted
    :param organization_id: organization where the content view was created
    """
    return hammer('content-view version promote --content-view {0} --id {1} '
                  '--lifecycle-environment-id {2} --organization-id 1'
                  .format(cv_name, cv_ver_id, lc_env_id))


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
        name, organization_id, product_name):
    """Add a subscription to an activation key

    :param name: name of the activation key which the subscription will be
        added
    :param organization_id: organization where the activation key was created
    :param product_name: product name whose subscription will be added to the
        activation key
    """
    subscription_id = get_product_subscription_id(
        organization_id, product_name)
    return hammer(
        'activation-key add-subscription --name "{0}" '
        '--organization-id "{1}" '
        '--subscription-id "{2}"'
        .format(name, organization_id, subscription_id)
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


@task
def hammer_activation_key_content_override(
        ak_name, content_label, value, org_id):
    """Override Content value in Product Content of Actiavaton Key.

    :param ak_name: AK name in which contnets to be overrided
    :param content_label: Content name of to be overrided
    :param value: True/False for override to yes/no
    :param org_id: The organization to which AK belongs
    """
    ak_id = get_attribute_value(
        hammer('activation-key list --organization-id {}'.format(org_id)),
        ak_name,
        'id'
    )
    return hammer(
        'activation-key content-override --id {0} '
        '--content-label {1} --value {2}'.format(
            ak_id, content_label, value))


def sync_capsule_content(capsule, async=True):
    """Start content synchronization in the capsule.

    If The content synchronization is asynchronous, check the capsule
    logs to see when it have finished.

    :param dict capsule: A capsule dictionary containing its ``id`` and
        ``name``.
    """
    if capsule['id'] == 1:
        print('Skipping default capsule...')
        return
    lcenvs = hammer_capsule_lcenvs(capsule['id'])
    for lcenv in lcenvs:
        hammer_capsule_add_lcenv(capsule['id'], lcenv['id'])
    if async is False:
        hammer('capsule content synchronize --id {0}'.format(capsule['id']))
    else:
        hammer('capsule content synchronize --async --id {0}'.format(
            capsule['id']))


def get_product_subscription_id(organization_id, product_name):
    """Returns products subscription id

    :param string organization_id: Organization Id in which product is created
    :param string product_name: Product name of which subscription id to return
    """
    return get_attribute_value(
        hammer('subscription list --organization-id {}'.format(
            organization_id)),
        product_name,
        'id')


def attach_subscription_to_host_from_satellite(
        organization_id, product_name, hostname):
    """Attaches product subscription to content host from satellite

    :param string organization_id: Organization Id in which product is created
    :param string product_name: Product name which to be added to content host
    :param string hostname: The hostname into which the product subscription
        will be added
    """
    subscription_id = get_product_subscription_id(
        organization_id, product_name)
    return hammer('host subscription attach --subscription-id {0} '
                  '--host {1}'.format(subscription_id, hostname))


def hammer_determine_cv_and_env_from_ak(ak_name, organization_id):
    """Determines Content View and Lifecycle Environment from
    Activation Key

    :param string ak_name: Activation key name
    :param int organization_id: Organization id in which ak created
    :returns dictionary containing cv and lenv as keys with names as
        their values
    """
    data = hammer('activation-key info --name {0} --organization-id '
                  '{1}'.format(ak_name, organization_id))
    if not isinstance(data, (dict, list)):
        raise KeyError(
            'Wrong Activation key provided for determining CV and Env')
    return get_attribute_value(data, ak_name, 'content view'), \
        get_attribute_value(data, ak_name, 'lifecycle environment')
