"""Tasks for base image creation and deployment"""
from __future__ import print_function

import os
import time

from fabric.api import env, get, put, run, settings
from re import search, MULTILINE

from six.moves.urllib.parse import urljoin


def detect_imagename(os_url):
    """Task to detect image name by OS URL

    :param str os_url: URL of OS media to detect

    """
    comp_id = run('wget -q -O- {}'.format(urljoin(os_url, '../../../../COMPOSE_ID')), quiet=True)
    if comp_id.succeeded:
        match_comp = search(r'(\w+)-([\d\.]+)-(?:\w+-)?([\d\.]+)', comp_id)
        image = match_comp.group(1).lower() + match_comp.group(2).replace('.', '') + '-' + \
            match_comp.group(3)
    else:
        image = 'unknown-{}'.format(str(time.time()).split('.')[0])

    print(image)
    return(image)


def create_baseimage(os_url, image=None, auth_keys_url=None, dns_server=None, disable_ipv6=False):
    """Task to create standard base image using OS URL

    :param str os_url: URL of OS media to install
    :param str image: Image name to be created (without extension .img)
    :param str auth_keys_url: authorized_keys file URL to be put in baseimage
    :param str dns_server: Custom DNS server to be set in baseimage
    :param bool disable_ipv6: Flag to have IPv6 networking disabled (=True) or enabled (=False)

    """
    if not os_url.endswith('/'):
        os_url += '/'
    if isinstance(disable_ipv6, str):
        disable_ipv6 = (disable_ipv6.lower() == 'true')

    # Detect OS version
    media = run('wget -q -O- {}'.format(urljoin(os_url, 'media.repo')))
    if media.succeeded:
        match_name = search(r'^name\s*=\s*(\D*)\s+([\d\.]*)', media, MULTILINE)
        if match_name:
            os_ver = match_name.group(2).split('.')[0]
        else:
            os_ver = 7

    if not image:
        image = detect_imagename(os_url)

    put('misc/base_image_creation/ks_rhel{}_template'.format(os_ver), 'ks.cfg')
    run('sed -i "s|OS_URL|{}|g" ks.cfg'.format(os_url))
    run(r'sed -i "s|ENCRYPT_PASS|\\$1\\$xyz\\$7xHVh4/yhE6P00NIXbWZA/|g" ks.cfg')
    run('sed -i "s|AUTH_KEYS_URL|{}|g" ks.cfg'.format(auth_keys_url))
    if not disable_ipv6:
        run('sed -i "/disable_ipv6/d" ks.cfg')
    if dns_server:
        run('sed -i "s|NAMESERVER|{}|g" ks.cfg'.format(dns_server))
    else:
        run(r'sed -i "\|/etc/resolv.conf|d" ks.cfg')

    run('virsh undefine {}'.format(image), warn_only=True)
    run('virt-install --connect qemu:///system -n {img} -l {url} -w bridge:br0 '
        '--initrd-inject ks.cfg -x "ks=file:/ks.cfg console=tty0 console=ttyS0,115200" '
        '--disk path=/var/lib/libvirt/images/{img}.img,size=200,device=disk,bus=virtio,format=raw,'
        'sparse=true --memory 4096 --vcpus 2 --cpu host --check-cpu --accelerate --hvm --force '
        '--graphics vnc,listen=0.0.0.0 --clock offset=localtime'
        .format(img=image, url=os_url))
    time.sleep(30)
    run('virsh destroy {}'.format(image))

    return image


def deploy_baseimage(image, hypervisors=[]):
    """Task to deploy specific image to set of hypervisors

    The following environment variables affect this command:

    PROVISIONING_HOSTS
        Set of hypervisor FQDNs/IPs to deploy image to

    :param str image: Image name to be deployed (without extension .img)
    :param list hypervisors: Set of hypervisor FQDNs/IPs to deploy image to

    """
    hypervisors = hypervisors or os.environ.get('PROVISIONING_HOSTS', '')
    if isinstance(hypervisors, str):
        hypervisors = hypervisors.split()

    tmpimg = run('mktemp')
    run('qemu-img convert /var/lib/libvirt/images/{}.img -O qcow2 {}'.format(image, tmpimg))
    src_fqdn = run('hostname')

    for target in hypervisors:
        if target == src_fqdn:  # omit image hosting machine from deployment
            continue
        if env.forward_agent:  # set by `-A` fab option and ssh agent must be available
            run('scp -p {} {}:{}'.format(tmpimg, target, tmpimg), warn_only=True)
        else:  # no ssh agent, scp works only 3way
            get(tmpimg, tmpimg)
            with settings(host_string=target):
                put(tmpimg, tmpimg)

        with settings(host_string=target):
            run('qemu-img convert {} -O raw /var/lib/libvirt/images/{}.img'.format(tmpimg, image))
            run('rm -f {}'.format(tmpimg))

    run('rm -f {}'.format(tmpimg))


def deploy_baseimage_by_url(os_url, **kwargs):
    """Task to create standard base image using OS URL and deploy it to set of hypervisors

    :param str os_url: URL of OS media to install

    """
    hypervisors = kwargs.pop('hypervisors', None)
    deploy_baseimage(create_baseimage(os_url, **kwargs), hypervisors=hypervisors)
