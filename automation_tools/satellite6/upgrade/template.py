from automation_tools.satellite6.hammer import hammer, set_hammer_config
from automation_tools.satellite6.upgrade import \
    check_necessary_env_variables_for_upgrade
from automation_tools.satellite6.upgrade.tasks import \
    get_rhevm_client, wait_till_rhev_instance_status
from fabric.api import run, execute
from ovirtsdk.xml import params
from time import sleep
import os
import sys


# Restart the Services
def service_restart():
    try:
        services = run('katello-service restart')
        if services.return_code > 0:
            sys.exit(1)
    except Exception as ex:
        print ex
        sys.exit(1)


# Running capsule sync on external capsule
def check_capsule():
    set_hammer_config(user=None, password=None)
    try:
        capsules = hammer('capsule list')
        cap_id = 0
        for item in capsules:
            if str(item[u'name']).__contains__("capsule"):
                cap_id = str(item[u'id'])
                print cap_id
        check = hammer("capsule refresh-features --id {0}".format(cap_id))
        print check[u'message']
        if check.return_code == 0:
            print "running capsule sync"
    except Exception as ex:
        print ex
        sys.exit(1)


# Check if ntpd is running
def check_ntpd():
    try:
        ntpd_check = run("service ntpd status", warn_only=True)
        if ntpd_check.return_code > 0:
            run("service ntpd start")
            run("chkconfig ntpd on")
    except Exception as ex:
        print ex
        sys.exit(1)


# Check for Vm's and create their templates
def create_template(host, cluster, new_template, storage):
    """ Create template from vmName """
    try:
        get_client = get_rhevm_client()
        storage_domain = get_client.storagedomains.get(name=storage)
        size = storage_domain.get_available() / 1024 / 1024 / 1024
        vm = get_rhevm_client().vms.get(host)
        if size > 300 and vm:
            try:
                vm.stop()
                wait_till_rhev_instance_status(host, 'down', 5)
                print 'Waiting for VM to reach Down status'
                get_client.templates.add(
                    params.Template(name=new_template,
                                    vm=get_client.vms.get(host),
                                    cluster=get_client.clusters.get(cluster)))
                while get_client.vms.get(host).status.state != 'down':
                    sleep(1)
                    "Template creation in Progress"
            except Exception as ex:
                get_client.disconnect()
                print 'Failed to Create Template from VM:\n%s' % str(ex)
        else:
            get_client.disconnect()
            print "Low Storage cannot proceed or VM not found"
            sys.exit(1)
    except Exception as ex:
        get_client.disconnect()
        print ex
        sys.exit(1)


# Fabric task
def validate_and_create():
    sat_host = os.environ.get('RHEV_SAT_HOST')
    cap_host = os.environ.get('RHEV_CAP_HOST')
    cluster = 'Default'
    storage = os.environ.get('RHEV_STORAGE')
    for host in sat_host, cap_host:
        if host == sat_host:
            image = os.environ.get('RHEV_SAT_IMAGE')
            sat_host = os.environ.get('RHEV_SAT_HOST')
            new_template = image + "_new"
            if check_necessary_env_variables_for_upgrade('capsule'):
                try:
                    execute(check_ntpd, host)
                    execute(service_restart, host)
                    execute(check_capsule, host)
                    create_template(sat_host, cluster, new_template, storage)
                except Exception as ex:
                    print ex
                    print "Satellite Validation or Template creation Failed"
                    sys.exit(1)
        else:
            image = os.environ.get('RHEV_CAP_IMAGE')
            cap_host = os.environ.get('RHEV_CAP_HOST')
            new_template = image + "_new"
            if check_necessary_env_variables_for_upgrade('capsule'):
                try:
                    execute(check_ntpd, host)
                    execute(service_restart, host)
                    create_template(cap_host, cluster, new_template, storage)
                except Exception as ex:
                    print ex
                    print "Capsule Validation or Template creation Failed"
                    sys.exit(1)
