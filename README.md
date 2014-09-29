automation-tools
================

A set of tools to help automating virtual machines to install Foreman and test it using Robottelo (https://github.com/omaciel/robottelo)

Usage examples
==============

Virtual Machine Management
--------------------------

To create a virtual machine will be needed a base image, to list all available base images:

    fab -H root@example.com vm_list_base

Creating a virtual machine:

    VM_RAM=512 VM_CPU=1 VM_DOMAIN=domain.example.com SOURCE_IMAGE=rhel7-base TARGET_IMAGE=test01 fab -H root@example.com vm_create

Destroying a virtual machine:

    fab -H root@example.com vm_destroy:test01,delete_image=True

Listing virtual machines:

    fab -H root@example.com vm_list

Subscription Management
-----------------------

Subscribe:

    DISTRO=rhel7 RHN_USERNAME=user@example.com RHN_PASSWORD=mysecret RHN_POOLID=poolid fab -H root@example.com subscribe

Unsubscribe:

    fab -H root@example.com unsubscribe

Satellite Installation
----------------------

Complete Satellite installation:

    DISTRO=rhel7 RHN_USERNAME=user@example.com RHN_PASSWORD=mysecret RHN_POOLID=poolid BASE_URL=http://example.com/Satellite/x86_64/os/ fab -H root@example.com subscribe install_prerequisites install_satellite setup_default_capsule

CDN Satellite installation:

    DISTRO=rhel7 fab -H root@example.com cdn_install setup_default_capsule

Installing nightly builds:

    DISTRO=rhel7 RHN_USERNAME=user@example.com RHN_PASSWORD=mysecret RHN_POOLID=poolid fab -H root@example.com subscribe install_prerequisites install_nightly

All installer tasks will setup the admin password to `changeme`.

Miscellaneous
-------------

Fabric will use your default ssh key, but if you want specify a different one, use the `-i` option:

    fab -i path/to/my_ssh_key.pub task
