# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from fabric.operations import run
from fabric.tasks import execute


class LogAnalyzer(object):
    """Context Manager to analyze changes in logs during some process.
    Example:

    >>> from automation_tools.satellite6.log import LogAnalyzer
    >>> with LogAnalyzer('root@sathost.redhat.com'):
    ...     print('Running some process, could be Satellite Upgrade')
    ...
    [root@sathost.redhat.com] Executing task 'get_line_count'
    Running some process, could be Satellite Upgrade
    [root@sathost.redhat.com] Executing task 'get_line_count'
    [root@sathost.redhat.com] Executing task 'fetch_appended_log_lines'
    ### No changes in /var/log/foreman-proxy/proxy.log
    ### No changes in /var/log/foreman/production.log
    ### No changes in /var/log/foreman-installer/satellite.log
    ### No changes in /var/log/candlepin/candlepin.log
    ### No changes in /var/log/tomcat/catalina.out
    ### No changes in /var/log/messages
    ### No changes in /var/log/mongodb/mongodb.log

    """

    def __init__(self, sat_host):
        """Initializes context manager with Satellite hostname

        :param sat_host: str
        """
        self.sat_host = sat_host
        self.log_state = {
            '/var/log/foreman-installer/satellite.log': 0,
            '/var/log/foreman/production.log': 0,
            '/var/log/foreman-proxy/proxy.log': 0,
            '/var/log/candlepin/candlepin.log': 0,
            '/var/log/messages': 0,
            '/var/log/mongodb/mongodb.log': 0,
            '/var/log/tomcat/catalina.out': 0
        }

    def __enter__(self):
        """
        Fetch current line count for Satellite log files
        :return: LogAnalyzer
        """
        self._update_log_files_state()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Analyzes log files checking if some error occurred since last
        log_state_dct
        """
        self._update_log_files_state()

        def analyze(log_file, content):
            """Analyzes appended content from log file. For now it is only
            printing content
            """
            print('### Analyzing %s:' % log_file)
            print(content)

        def fetch_appended_log_lines():
            for log_file, lines_appended in self.log_state.items():
                if lines_appended > 0:
                    content = run(
                        'tail -n {} {}'.format(lines_appended, log_file),
                        quiet=True
                    )
                    analyze(log_file, content)
                else:
                    print('### No changes in %s' % log_file)

        execute(fetch_appended_log_lines, host=self.sat_host)

    def _update_log_files_state(self):
        """Update log_dct with adding delta from current number of lines of
        each
        item and the last provided by dct. Ex:

        So this method can be used to check how many lines were appended on
        a file
        during some processes and used to tail them. If log dct is None a
        new dict
        is created

        :param sat_host: str with satellite hostname
        :param log_dct: dict to be updated
        """

        def get_line_count():
            for log_file, old_value in self.log_state.items():
                current_value = int(
                    run(
                        'wc -l < {}'.format(log_file),
                        quiet=True
                    )
                )
                self.log_state[log_file] = current_value - old_value

        execute(get_line_count, host=self.sat_host)
