#!/bin/bash
# Define a timestamp function
timestamp() {
  date +"%Y-%m-%d:%T"
}
echo "$(timestamp): Cleaning UP of Virtual Machines BEGINS" >> /var/log/cleanup_vms.log 2>&1
virsh list | grep -ve qe -ve Name | awk '{print $2}' > /root/vm_list.txt
for i in `cat /root/vm_list.txt`; do virsh destroy $i; virsh undefine $i; virsh vol-delete --pool default  /opt/robottelo/images/$i.img; done >> /var/log/cleanup_vms.log 2>&1
echo "$(timestamp): Cleaning UP of Virtual Machines END" >> /var/log/cleanup_vms.log 2>&1
