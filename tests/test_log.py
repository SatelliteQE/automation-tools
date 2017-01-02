# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

from automation_tools.satellite6.log import LogAnalyzer, analyze


@pytest.fixture(autouse=True)
def execute(mocker):
    """Mock fabric's execute function to avoid call through network"""
    execute_mock = mocker.patch('automation_tools.satellite6.log.execute')

    def execute_function_argmument(function, host):
        function()
        return host

    execute_mock.side_effect = execute_function_argmument
    return execute_mock


def run_mock_helper(mocker, return_value):
    """Helper to mock run"""
    run_mock = mocker.patch('automation_tools.satellite6.log.run')
    run_mock.return_value = return_value
    return run_mock


@pytest.fixture
def run_50(mocker):
    """Mock fabric's run function to avoid call through network. return
    string 50 all the time run is executed"""
    return run_mock_helper(mocker, '50')


@pytest.fixture
def run_with_error(mocker):
    """Mock fabric's run function to avoid call through network. return
    string with file not available"""
    return run_mock_helper(
        mocker,
        '/bin/bash: /var/log/foreman-installer/satellite.log: No such file '
        'or directory')


def test_log_analyzer_enter(run_50):
    """Check with __enter__ calls fabric functions to get log files state"""
    analyzer = LogAnalyzer('root@foo.bar')
    analyzer.__enter__()
    expected_state = {
        '/var/log/foreman-installer/satellite.log': 50,
        '/var/log/foreman-installer/capsule.log': 50,
        '/var/log/satellite-installer/satellite-installer.log': 50,
        '/var/log/capsule-installer/capsule-installer.log': 50,
        '/var/log/foreman/production.log': 50,
        '/var/log/foreman-proxy/proxy.log': 50,
        '/var/log/candlepin/candlepin.log': 50,
        '/var/log/messages': 50,
        '/var/log/mongodb/mongodb.log': 50,
        '/var/log/tomcat/catalina.out': 50
    }
    assert analyzer.log_state == expected_state
    assert run_50.call_count == len(expected_state)
    for log_file in expected_state:
        run_50.assert_any_call('wc -l < %s' % log_file, quiet=True)

    # Assertiing calling enter again will calculate delta
    run_50.return_value = 55

    analyzer._update_log_files_state()  # noqa

    for lines_appended in analyzer.log_state.values():
        assert 5 == lines_appended  # result of 55 - 50


def test_log_analyzer_exit(mocker):
    """Check exit get lines appended on log files"""
    analyzer = LogAnalyzer('root@foo.bar')

    # Mocking
    analyzer._update_log_files_state = mocker.Mock()  # noqa

    # Defining log state with files with and without lines appended
    log_with_lines_appended = {
        '/var/log/candlepin/candlepin.log': 1,
        '/var/log/messages': 2,
        '/var/log/mongodb/mongodb.log': 3,
        '/var/log/tomcat/catalina.out': 4
    }

    log_without_lines_appended = {
        '/var/log/foreman-installer/satellite.log': 0,
        '/var/log/foreman/production.log': -1,
        '/var/log/foreman-proxy/proxy.log': 0,
    }

    analyzer.log_state.update(log_with_lines_appended)
    analyzer.log_state.update(log_without_lines_appended)

    # Defining contest which will be returned for files with lines appended
    log_files_content = {
        '/var/log/candlepin/candlepin.log': 'foo',
        '/var/log/messages': 'bar',
        '/var/log/mongodb/mongodb.log': 'baz',
        '/var/log/tomcat/catalina.out': 'blah'
    }

    def tail_side_effect(tail_cmd, quiet):
        assert quiet
        for log_file, content in log_files_content.items():
            if tail_cmd.endswith(log_file):
                return content

    run_mock = mocker.patch('automation_tools.satellite6.log.run')
    run_mock.side_effect = tail_side_effect

    analyze_mock = mocker.patch('automation_tools.satellite6.log.analyze')

    analyzer.__exit__(None, None, None)

    analyzer._update_log_files_state.assert_called_once_with()  # noqa

    assert run_mock.call_count == len(log_with_lines_appended)

    for log_file, lines_appended in log_with_lines_appended.items():
        run_mock.assert_any_call(
            'tail -n {} {}'.format(lines_appended, log_file), quiet=True)

    assert analyze_mock.call_count == len(log_with_lines_appended)
    for log_file, content in log_files_content.items():
        analyze_mock.assert_any_call(log_file, content)


def test_log_analyzer_file_not_available(run_with_error):
    # Testing enter
    not_zero_state = {
        '/var/log/foreman-installer/satellite.log': 50,
        '/var/log/foreman/production.log': 50,
        '/var/log/foreman-proxy/proxy.log': 50,
        '/var/log/candlepin/candlepin.log': 50,
        '/var/log/messages': 50,
        '/var/log/mongodb/mongodb.log': 50,
        '/var/log/tomcat/catalina.out': 50
    }
    analyzer = LogAnalyzer('root@foo.bar')
    analyzer.log_state = dict(not_zero_state.items())
    analyzer.__enter__()
    assert run_with_error.call_count == len(not_zero_state)
    for line_appended in analyzer.log_state.values():
        assert 0 == line_appended

    # Testing exit
    run_with_error.reset_mock()
    analyzer.log_state = dict(not_zero_state.items())
    analyzer.__exit__(None, None, None)
    assert run_with_error.call_count == len(not_zero_state)
    for line_appended in analyzer.log_state.values():
        assert 0 == line_appended


@pytest.fixture
def print_mock(mocker):
    """Mock _print_wrapper function"""
    return mocker.patch('automation_tools.satellite6.log._print_wrapper')


CONTENT_WITHOUT_ERROR = '''2016-11-23 05:41:54 [app] [I] Processing by Api::
2016-11-23 05:41:54 [app] [I] Parameters: {"report"=>"[FILTERED]", "apiv"=>
2016-11-23 05:41:54 [app] [I] processing report for
2016-11-23 05:41:54 [app] [I] Imported report for
2016-11-23 05:41:55 [app] [I] Rendered api/v2/reports/create.json (5.5ms)
2016-11-23 05:41:55 [app] [I] Completed 201 Created in 61ms'''.encode('utf-8')

REPORT_WITHOUT_ERROR = '''### Analyzing /var/log/candlepin/candlepin.log:
## Errors found:
## Full log:
1: 2016-11-23 05:41:54 [app] [I] Processing by Api::
2: 2016-11-23 05:41:54 [app] [I] Parameters: {"report"=>"[FILTERED]", "apiv"=>
3: 2016-11-23 05:41:54 [app] [I] processing report for
4: 2016-11-23 05:41:54 [app] [I] Imported report for
5: 2016-11-23 05:41:55 [app] [I] Rendered api/v2/reports/create.json (5.5ms)
6: 2016-11-23 05:41:55 [app] [I] Completed 201 Created in 61ms'''

CONTENT_WITH_ERROR = '''c75ff8b-2ee0-4a6a-a94e-, org=] ERROR  org.
SEVERE: The web application [/gutterball] registered the JDBC driver
NO problem on this line
Exception in thread "Resource Destroyer in BasicResourcePool.close()"
javax.persistence.PersistenceException: unexpected error when rollbacking
Could not find the inverse association for repository
PG::Error: ERROR: update or delete on table
NoMethodError: undefined method
usr/sbin/foreman-rake db:migrate returned 1 instead of one of [0]
/usr/sbin/foreman-rake db:seed returned 1 instead of one of [0]
[E] undefined method `finished' for nil:NilClass (NoMethodError)
[ProxyAPI::ProxyException]: Unable to detect
(ActiveModel::MissingAttributeError)
ActionView::Template::Error (undefined method
undefined method `cp_config' for
An error has occurred, this and all later migrations canceled
undefined method `import_data' for nil:NilClass (NoMethodError)
undefined method `[]' for nil:NilClass (NoMethodError)'''.encode('utf-8')

REPORT_WITH_ERROR = '''### Analyzing /var/log/candlepin/candlepin.log:
## Errors found:
1: c75ff8b-2ee0-4a6a-a94e-, org=] ERROR  org.
2: SEVERE: The web application [/gutterball] registered the JDBC driver
4: Exception in thread "Resource Destroyer in BasicResourcePool.close()"
5: javax.persistence.PersistenceException: unexpected error when rollbacking
6: Could not find the inverse association for repository
7: PG::Error: ERROR: update or delete on table
8: NoMethodError: undefined method
9: usr/sbin/foreman-rake db:migrate returned 1 instead of one of [0]
10: /usr/sbin/foreman-rake db:seed returned 1 instead of one of [0]
11: [E] undefined method `finished' for nil:NilClass (NoMethodError)
12: [ProxyAPI::ProxyException]: Unable to detect
13: (ActiveModel::MissingAttributeError)
14: ActionView::Template::Error (undefined method
15: undefined method `cp_config' for
16: An error has occurred, this and all later migrations canceled
17: undefined method `import_data' for nil:NilClass (NoMethodError)
18: undefined method `[]' for nil:NilClass (NoMethodError)
## Full log:
1: c75ff8b-2ee0-4a6a-a94e-, org=] ERROR  org.
2: SEVERE: The web application [/gutterball] registered the JDBC driver
3: NO problem on this line
4: Exception in thread "Resource Destroyer in BasicResourcePool.close()"
5: javax.persistence.PersistenceException: unexpected error when rollbacking
6: Could not find the inverse association for repository
7: PG::Error: ERROR: update or delete on table
8: NoMethodError: undefined method
9: usr/sbin/foreman-rake db:migrate returned 1 instead of one of [0]
10: /usr/sbin/foreman-rake db:seed returned 1 instead of one of [0]
11: [E] undefined method `finished' for nil:NilClass (NoMethodError)
12: [ProxyAPI::ProxyException]: Unable to detect
13: (ActiveModel::MissingAttributeError)
14: ActionView::Template::Error (undefined method
15: undefined method `cp_config' for
16: An error has occurred, this and all later migrations canceled
17: undefined method `import_data' for nil:NilClass (NoMethodError)
18: undefined method `[]' for nil:NilClass (NoMethodError)'''

CONTENT_WITH_SPECIAL_CHAR = 'éçã'.encode('utf-8')

REPORT_WITH_SPECIAL_CHAR = '''### Analyzing /var/log/candlepin/candlepin.log:
## Errors found:
## Full log:
1: éçã'''
test_data = [
    (CONTENT_WITHOUT_ERROR, REPORT_WITHOUT_ERROR),
    (CONTENT_WITH_ERROR, REPORT_WITH_ERROR),
    (CONTENT_WITH_SPECIAL_CHAR, REPORT_WITH_SPECIAL_CHAR)]

ids = ['without error', 'with error', 'special char']


@pytest.mark.parametrize("content,report", test_data, ids=ids)
def test_analyse(content, report, print_mock):
    """Test analyse find no errors on file content"""
    log_file = '/var/log/candlepin/candlepin.log'
    analyze(log_file, content)
    args = [
        positional_args[0] for positional_args, _ in print_mock.call_args_list
    ]
    assert '\n'.join(args) == report
