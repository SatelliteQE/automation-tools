# -*- encoding: utf-8 -*-
"""
Collection of functions to work with Bugzilla and Redmine.
copied from robottelo's robotello/decorators/__init__.py
"""
import bugzilla
import logging
import requests

from six.moves.xmlrpc_client import Fault
from xml.parsers.expat import ExpatError, ErrorString

BZ_OPEN_STATUSES = [
    'NEW',
    'ASSIGNED',
    'POST',
    'MODIFIED',
    'ON_DEV'
]
BUGZILLA_URL = "https://bugzilla.redhat.com/xmlrpc.cgi"
LOGGER = logging.getLogger(__name__)
OBJECT_CACHE = {}
REDMINE_URL = 'http://projects.theforeman.org'

# A cache mapping bug IDs to python-bugzilla bug objects.
_bugzilla = {}

# A cache used by redmine-related functions.
# * _redmine['closed_statuses'] is used by `_redmine_closed_issue_statuses`
#
_redmine = {
    'closed_statuses': None,
    'issues': {},
}


class BugFetchError(Exception):
    """Indicates an error occurred while fetching information about a bug."""


def _get_bugzilla_bug(bug_id):
    """Fetch bug ``bug_id``.

    :param int bug_id: The ID of a bug in the Bugzilla database.
    :return: A FRIGGIN UNDOCUMENTED python-bugzilla THING.
    :raises BugFetchError: If an error occurs while fetching the bug. For
        example, a network timeout occurs or the bug does not exist.

    """
    # Is bug ``bug_id`` in the cache?
    if bug_id in _bugzilla:
        LOGGER.debug('Bugzilla bug {0} found in cache.'.format(bug_id))
    else:
        LOGGER.info('Bugzilla bug {0} not in cache. Fetching.'.format(bug_id))
        # Make a network connection to the Bugzilla server.
        try:
            bz_conn = bugzilla.RHBugzilla()
            bz_conn.connect(BUGZILLA_URL)
        except (TypeError, ValueError):
            raise BugFetchError(
                'Could not connect to {0}'.format(BUGZILLA_URL)
            )
        # Fetch the bug and place it in the cache.
        try:
            _bugzilla[bug_id] = bz_conn.getbugsimple(bug_id)
        except Fault as err:
            raise BugFetchError(
                'Could not fetch bug. Error: {0}'.format(err.faultString)
            )
        except ExpatError as err:
            raise BugFetchError(
                'Could not interpret bug. Error: {0}'
                .format(ErrorString(err.code))
            )

    return _bugzilla[bug_id]


def _redmine_closed_issue_statuses():
    """Return a list of issue status IDs which indicate an issue is closed.

    This list of issue status IDs is not hard-coded. Instead, the Redmine
    server is consulted when generating this list.

    :return: Statuses which indicate an issue is closed.
    :rtype: list

    """
    # Is the list of closed statuses cached?
    if _redmine['closed_statuses'] is None:
        result = requests.get('%s/issue_statuses.json' % REDMINE_URL).json()
        # We've got a list of *all* statuses. Let's throw only *closed*
        # statuses in the cache.
        _redmine['closed_statuses'] = []
        for issue_status in result['issue_statuses']:
            if issue_status.get('is_closed', False):
                _redmine['closed_statuses'].append(issue_status['id'])

    return _redmine['closed_statuses']


def _get_redmine_bug_status_id(bug_id):
    """Fetch bug ``bug_id``.

    :param int bug_id: The ID of a bug in the Redmine database.
    :return: The status ID of that bug.
    :raises BugFetchError: If an error occurs while fetching the bug. For
        example, a network timeout occurs or the bug does not exist.

    """
    if bug_id in _redmine['issues']:
        LOGGER.debug('Redmine bug {0} found in cache.'.format(bug_id))
    else:
        # Get info about bug.
        LOGGER.info('Redmine bug {0} not in cache. Fetching.'.format(bug_id))
        result = requests.get(
            '{0}/issues/{1}.json'.format(REDMINE_URL, bug_id)
        )
        if result.status_code != 200:
            raise BugFetchError(
                'Redmine bug {0} does not exist'.format(bug_id)
            )
        result = result.json()

        # Place bug into cache.
        try:
            _redmine['issues'][bug_id] = result['issue']['status']['id']
        except KeyError as err:
            raise BugFetchError(
                'Could not get status ID of Redmine bug {0}. Error: {1}'.
                format(bug_id, err)
            )

    return _redmine['issues'][bug_id]


def bz_bug_is_open(bug_id, upstream=False):
    """Tell whether Bugzilla bug ``bug_id`` is open.

    If information about bug ``bug_id`` cannot be fetched, the bug is assumed
    to be closed.

    :param bug_id: The ID of the bug being inspected.
    :param bool upstream: Flag whether we run on upstream.
    :return: ``True`` if the bug is open. ``False`` otherwise.
    :rtype: bool

    """
    bug = None
    try:
        bug = _get_bugzilla_bug(bug_id)
    except BugFetchError as err:
        LOGGER.warning(err)
        return False
    # NOT_FOUND, ON_QA, VERIFIED, RELEAEE_PENDING, CLOSED
    if bug is None or bug.status not in BZ_OPEN_STATUSES:
        return False
    # running on upstream and whiteboard is 'Verified in Upstream'
    elif (upstream and
          bug.whiteboard and 'verified in upstream' in bug.whiteboard.lower()):
        return False
    # NEW, ASSIGNED, MODIFIED, POST, ON_DEV
    return True


def rm_bug_is_open(bug_id):
    """Tell whether Redmine bug ``bug_id`` is open.

    If information about bug ``bug_id`` cannot be fetched, the bug is assumed
    to be closed.

    :param bug_id: The ID of the bug being inspected.
    :return: ``True`` if the bug is open. ``False`` otherwise.
    :rtype: bool

    """
    status_id = None
    try:
        status_id = _get_redmine_bug_status_id(bug_id)
    except BugFetchError as err:
        LOGGER.warning(err)
    if status_id is None or status_id in _redmine_closed_issue_statuses():
        return False
    return True
