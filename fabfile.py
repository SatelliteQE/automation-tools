"""Module which publish all automation-tools tasks"""
from automation_tools import (  # flake8: noqa
    add_repo,
    cdn_install,
    clean_rhsm,
    client_registration_test,
    create_personal_git_repo,
    download_manifest,
    downstream_install,
    enable_gateway_ports_connections,
    errata_upgrade,
    fix_hostname,
    fix_qdrouterd_listen_to_ipv6,
    foreman_debug,
    idp_authenticate,
    install_errata,
    install_katello_agent,
    install_prerequisites,
    iso_download,
    iso_install,
    katello_service,
    partition_disk,
    performance_tuning,
    product_install,
    remove_katello_agent,
    relink_manifest,
    run_errata,
    set_service_check_status,
    set_yum_debug_level,
    setup_abrt,
    setup_ddns,
    setup_default_capsule,
    setup_default_docker,
    setup_email_notification,
    setup_fake_manifest_certificate,
    setup_firewall,
    setup_capsule_firewall,
    setup_satellite_firewall,
    setup_libvirt_key,
    setup_proxy,
    setup_vm_provisioning,
    subscribe,
    unsubscribe,
    update_basic_packages,
    update_rhsm_stage,
    upstream_install,
    vm_create,
    vm_destroy,
    vm_list,
    vm_list_base,
)
from automation_tools.repository import (
    create_custom_repos,
    delete_custom_repos,
    disable_beaker_repos,
    disable_repos,
    enable_repos,
    enable_satellite_repos,
    manage_custom_repos,
)
from automation_tools.satellite5 import (
    satellite5_installer,
    satellite5_product_install,
)
from automation_tools.utils import (
    distro_info,
    update_packages
)
from automation_tools.satellite6.upgrade import (
    product_upgrade,
    satellite6_capsule_upgrade,
    satellite6_upgrade
)
from automation_tools.satellite6.upgrade.tasks import (
    create_openstack_instance,
    create_rhevm_instance,
    delete_openstack_instance,
    delete_rhevm_instance,
    reboot_rhevm_instance,
    sync_capsule_tools_repos_to_upgrade,
    wait_till_rhev_instance_status
)
from automation_tools.satellite6.upgrade.tools import (
    copy_ssh_key,
    get_hostname_from_ip,
    host_pings,
    reboot
)