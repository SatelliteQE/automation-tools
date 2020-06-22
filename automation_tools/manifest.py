"""Tasks for manifest deployment and manipulation"""
from __future__ import print_function

import base64
import os
import sys

from datetime import date
from fabric.api import run


def read_subs(exp_subs_file):
    """Function returning expected subscriptions dictionary being read from a file

    :param exp_subs_file: Expected subscription file
    :returns: dictionary containing expected subscriptions { name: [ pool_id, amount ] }
    """
    with open(exp_subs_file, 'r') as fp:
        exp_subs_details = [
            r.strip().split(';') for r in fp.readlines() if not r.strip().startswith('#')
        ]
    return {exp_sub[0]: exp_sub[1:] for exp_sub in exp_subs_details}


def download_manifest(url, consumer, user, password):
    """Task for downloading the manifest file from customer portal.

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :returns: a path string to a downloaded manifest file
    """
    string = u'{0}:{1}'.format(user, password)

    if isinstance(string, str):  # py3
        bytestring = bytes('{0}:{1}'.format(user, password), 'utf-8')
    else:  # py2
        bytestring = bytes('{0}:{1}'.format(user, password))

    base64string = base64.encodestring(bytestring).strip()

    manifest_file = run('mktemp --suffix=.zip')

    # we do this as we would otherwise potentially download a manifest which
    # has new metadata (such as new content sets/repos) but does not have the
    # required Entitlement certificates to actually access the content.
    certs_put = ('curl -sk -X PUT -H "Authorization:Basic {0}"'
                 ' {1}/subscription/consumers/{2}/certificates'
                 '?lazy_regen=false').format(
                 base64string.decode('utf-8'), url, consumer)
    run(certs_put)

    command = ('curl -sk -H "Authorization:Basic {0}"'
               ' {1}/subscription/consumers/{2}/export/').format(
               base64string.decode('utf-8'), url, consumer)

    response = run(command + ' -I')
    if ('Content-Disposition: attachment' in response):
        run(command + ' -o {0}'.format(manifest_file))
        return manifest_file
    else:
        raise ValueError('Request has returned no attachment. Check the'
                         ' session and distributor hash')


def attach_subscription(user, password, url, consumer, pool_id=None, count=None):
    """Task to attach subscription to manifest.

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :param pool_id: A pool ID of subscription
    :param count: A quantity of subscription requires to attach
    :returns: boolean True/False
    """
    auth_details = u'{0}:{1}'.format(user, password)

    if isinstance(auth_details, str):  # py3
        bytestring = bytes('{0}:{1}'.format(user, password), 'utf-8')
    else:  # py2
        bytestring = bytes('{0}:{1}'.format(user, password))

    base64string = base64.encodestring(bytestring).strip()

    url = url or os.environ.get('SM_URL')
    consumer = consumer or os.environ.get('CONSUMER')

    if pool_id and count:
        command = (
            'curl -sk -X POST -H "Authorization:Basic {0}" '
            '"{1}/subscription/consumers/{2}/entitlements?pool={3}&quantity={4}"'
        ).format(base64string.decode('utf-8'), url, consumer, pool_id, count)
        response = run(command)
        return 'updated' in response
    else:
        raise ValueError("Pass values under pool_id and count")


def delete_subscriptions(user, password, url, consumer):
    """Task to delete all subscriptions in manifest.

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :returns: boolean True/False
    """
    auth_details = u'{0}:{1}'.format(user, password)

    if isinstance(auth_details, str):  # py3
        bytestring = bytes('{0}:{1}'.format(user, password), 'utf-8')
    else:  # py2
        bytestring = bytes('{0}:{1}'.format(user, password))

    base64string = base64.encodestring(bytestring).strip()

    url = url or os.environ.get('SM_URL')
    consumer = consumer or os.environ.get('CONSUMER')

    command = (
        'curl -sk -X DELETE -H "Authorization:Basic {0}" '
        '"{1}/subscription/consumers/{2}/entitlements"'
    ).format(base64string.decode('utf-8'), url, consumer)
    response = run(command)
    return 'deletedRecords' in response


def read_manifest(manifest_file):
    """Reads subscriptions being carried in the manifest

    :param manifest_file: Specify the manifest file path
    :return: subscription list
    """
    rct_output = run("rct cat-manifest --no-content {}".format(manifest_file)).split("\n")
    sub_name_next = False
    current_subs = list()
    for r in rct_output:
        r = r.strip()
        if r == 'Subscription:':
            sub_name_next = True
            continue
        if sub_name_next:
            if r.startswith('Name: '):
                current_subs.append(r[6:])
            sub_name_next = False
    print('current subscriptions in {} are:\n - {}'
          .format(manifest_file, '\n - '.join(current_subs)))
    return current_subs


def validate_manifest(user, password, url, consumer, manifest_file, exp_subs_file):
    """Make sure that manifest contains only subscriptions specified in config file
    specified in variable and attach if missing any:

    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :param exp_subs_file: Expected subscription file
    :param manifest_file: Specify the manifest file path.
    :return: whether manifest required modification True/False
    """
    exp_subs = read_subs(exp_subs_file)
    print("expected subscriptions in {} are {}".format(manifest_file, ' & '.join(exp_subs.keys())))
    current_subs = read_manifest(manifest_file)

    modified = False
    for sub_name, sub_detail in exp_subs.items():
        if sub_name not in current_subs:
            print('Attaching missing subscription {}'.format(sub_name))
            attach = attach_subscription(user=user, password=password, url=url, consumer=consumer,
                                         pool_id=sub_detail[0], count=sub_detail[1])
            if attach:
                print('Successfully attached subscription {}'.format(sub_name))
                modified = True
            else:
                raise ValueError('Failed to attach subscription {}'.format(sub_name))
    return modified


def refresh_manifest(url, consumer, user, password, exp_subs_file):
    """Task to remove all subscriptions from manifest and attach required ones.

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :param exp_subs_file: Expected subscription file
    :returns: boolean True/False
    """
    print("Cleaning up all subscriptions from Manifest!")
    result = delete_subscriptions(user, password, url, consumer)

    if result:
        for sub_name, sub_detail in read_subs(exp_subs_file).items():
            print("Attaching subscription {}".format(sub_name))
            attach = attach_subscription(user=user, password=password, url=url, consumer=consumer,
                                         pool_id=sub_detail[0], count=sub_detail[1])
            if attach:
                print("Successfully attached subscription {}".format(sub_name))
            else:
                return attach
    return result


def relink_manifest(url, consumer, user, password, exp_subs_file, manifest_file=None):
    """Links the latest downloaded manifest file to the manifest_latest.zip softlink.

    :param url: Subscription Manager URL
    :param consumer: A consumer hash to be used for getting the manifest
    :param user: Red Hat Network username
    :param password: Red Hat Network password
    :param exp_subs_file: Expected subscription file
    :param manifest_file: Specify the manifest file path.
    """

    manifest_file = manifest_file or download_manifest(
        url=url, consumer=consumer, user=user, password=password)
    if not manifest_file:
        print('manifest_file is not populated.')
        sys.exit(1)

    if exp_subs_file:
        validate = validate_manifest(user=user, password=password, url=url, consumer=consumer,
                                     manifest_file=manifest_file, exp_subs_file=exp_subs_file)
        if validate:  # manifest was modified, so dowload manifest again
            manifest_file = download_manifest(url=url, consumer=consumer,
                                              user=user, password=password)
    date_str = date.today().strftime("%Y%m%d")
    new_manifest_file = '/opt/manifests/manifest-{0}.zip'.format(date_str)
    run('mv {0} {1}'.format(manifest_file, new_manifest_file))
    run('chmod 644 {0}'.format(new_manifest_file))
    run('restorecon -v {0}'.format(new_manifest_file))
    run('unlink /opt/manifests/manifest-latest.zip')
    run('ln -s {0} /opt/manifests/manifest-latest.zip'.format(new_manifest_file))
