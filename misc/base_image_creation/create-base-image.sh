#!/bin/bash
if [ "$1" == "-h" ] ; then
    echo "      Usage: `basename $0` [-h]"
    echo "          *******Example*******"
    echo "      Enter the Operating System version. (Ex: 6 or 7)"
    echo "      6"
    echo "      Enter the url of the Operating System."
    echo "      http://xxxxxx.com/Server/x86_64/os/"
    echo "      Enter the base image name.(Ex: rhel68 or rhel73)"
    echo "      rhel68"
    echo "      Enter the password for the base image."
    echo "      password"
    echo "      Enter the Authorized keys url for the base image. (Hosted authorized_keys file with jenkins key)"
    echo "      http://xxxxx.com/xxx/authorized_keys"
    exit 0
fi
echo "Enter the Operating System version. (Ex: 6 or 7)"
read os_version
echo "Enter the url of the Operating System."
read os_url
echo "Enter the base image name.(Ex: rhel68 or rhel73)"
read base_image
echo "Enter the password for the base image."
read pass
echo "Enter the Authorized keys url for the base image. (Hosted authorized_keys file with jenkins key)"
read auth_url
echo "Do you want to disable IPv6 in base image? (Y/n)"
read disable_ipv6

if [ $os_version -eq 6 ] ; then 
    cp ks_rhel6_template /root/base-image.ks
elif [ $os_version -eq 7 ] ; then
    cp ks_rhel7_template /root/base-image.ks
else 
    echo "OS Version can only be 6 or 7"
    exit
fi

if [[ $base_image == *"beta"* ]] ; then
    sed -i "s/enabled=0/enabled=1/g" /root/base-image.ks
fi

if [[ $disable_ipv6 =~ ^(n|N|no|No)$ ]] ; then
    sed -i "/disable_ipv6/d" /root/base-image.ks
fi

# | is used as $os_url also could contain '/'.
sed -i "s|OS_URL|$os_url|g" /root/base-image.ks
PASS=`openssl passwd -1 -salt xyz  $pass`
sed -i "s|ENCRYPT_PASS|'$PASS'|g" /root/base-image.ks
sed -i "s|AUTH_KEYS_URL|$auth_url|g" /root/base-image.ks


virt-install --connect=qemu:///system \
    --network=bridge:br0 \
    --initrd-inject=/root/base-image.ks \
    --extra-args="ks=file:/base-image.ks \
      console=tty0 console=ttyS0,115200" \
    --name=${base_image}-base \
    --disk path=/var/lib/libvirt/images/${base_image}-base.img,size=200,device=disk,bus=virtio,format=raw,sparse=true \
    --ram 4096 \
    --vcpus=2 \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$os_url \
    --cpu host \
    --graphics vnc,listen=0.0.0.0 \
    --clock offset=localtime \
    --force

# The argument `--cpu host` enables nested virtualization and is required to setup sat6 vms with provisioning support.
