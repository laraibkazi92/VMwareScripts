#!/bin/bash

# Author: Laraib Kazi

# Purpose of this script:
# Find any and all entries associated with a particular FQDN and IP and remove all entries associated with those
# from all known_hosts files in the SDDC Manager
# Once they are deleted, we add newly computed keyscans values to the known_hosts files

read -e -i "$fqdn" -p "Please enter the FQDN of the node we want to edit the known_hosts entry for: " input
fqdn="${input:-$fqdn}"
read -e -i "$ip" -p "Please enter the IP of the same node we want to edit the known_hosts entry for: " input
ip="${input:-$ip}"

echo "========================================================================================"
echo " Fetching all keys for node: $fqdn"
echo "========================================================================================"
echo " "

all_keys_fqdn=$(ssh-keyscan -4 $fqdn 2>/dev/null)
all_keys_ip=$(ssh-keyscan -4 $ip 2>/dev/null)

if [ -z "$all_keys_ip" ];
then
	echo "No keys found for node: $ip. Please check the IP."
else
	echo "Following Keys for Port 22 on $ip:"
	echo " "
	echo "$all_keys_ip"
	
	echo " "
	echo "========================================================================================"
	echo " Deleting existing stale entries for FQDN ..."

	# First we delete any entries that exist for the node $fqdn in the known_hosts files:
	sed -i "/$fqdn/d" /root/.ssh/known_hosts 2>/dev/null
	sed -i "/$fqdn/d" /etc/vmware/vcf/commonsvcs/known_hosts 2>/dev/null
	sed -i "/$fqdn/d" /home/vcf/.ssh/known_hosts 2>/dev/null 
	sed -i "/$fqdn/d" /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts 2>/dev/null
    
	echo " "
	echo " Deleting existing stale entries for IP ..."

	# Second, we delete any entries that exist for the node $ip in the known_hosts files
	sed -i "/$ip/d" /root/.ssh/known_hosts 2>/dev/null
	sed -i "/$ip/d" /etc/vmware/vcf/commonsvcs/known_hosts 2>/dev/null
	sed -i "/$ip/d" /home/vcf/.ssh/known_hosts 2>/dev/null 
	sed -i "/$ip/d" /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts 2>/dev/null

	echo " "
	echo "========================================================================================"
	echo " Adding new entries to known hosts"

	# Finally, adding new entries for the FQDN:
	echo -e "$all_keys_fqdn" >> /root/.ssh/known_hosts
	echo -e "$all_keys_ip" >> /root/.ssh/known_hosts 
	echo " >> Done >> /root/.ssh/known_hosts"
	echo -e "$all_keys_fqdn" >> /etc/vmware/vcf/commonsvcs/known_hosts
	echo -e "$all_keys_ip" >> /etc/vmware/vcf/commonsvcs/known_hosts
	echo " >> Done >> /etc/vmware/vcf/commonsvcs/known_hosts"
	echo -e "$all_keys_fqdn" >> /home/vcf/.ssh/known_hosts
	echo -e "$all_keys_ip" >> /home/vcf/.ssh/known_hosts
	echo " >> Done >> /home/vcf/.ssh/known_hosts"
	echo -e "$all_keys_fqdn" >> /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts
	echo -e "$all_keys_ip" >> /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts
	echo " >> Done >> /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts"
	echo "========================================================================================"
	echo " "
fi

echo " Checking and updating known_hosts files ownership and permissions"
echo " "

chmod 644 /root/.ssh/known_hosts
chown root:root /root/.ssh/known_hosts
chmod 644 /etc/vmware/vcf/commonsvcs/known_hosts
chown vcf_commonsvcs:vcf /etc/vmware/vcf/commonsvcs/known_hosts
chmod 644 /home/vcf/.ssh/known_hosts
chown vcf:vcf /home/vcf/.ssh/known_hosts
chmod 644 /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts
chown vcf_commonsvcs:vcf /opt/vmware/vcf/commonsvcs/defaults/hosts/known_hosts

curl -k -X POST http://localhost/appliancemanager/ssh/knownHosts/refresh

echo "Host Keys updated for $fqdn across all known_hosts files."
	