Un-official scripts for various workflows for various VMware products

```diff
- NOTE: These scripts are Un-official and are not approved or supported by VMware Engineering.
+ The only "Approved" and "Supported" scripts are the ones that are available in Public KBs
```


## nsxtVmcaCert.py
Script to generate, import and apply VMCA-signed Certificates (from a vCenter) to NSX-T Managers and VIP.

Needs to be run from a vCenter connected to the NSX-T environment.

Published in KB: https://kb.vmware.com/kb/89921

============================================================= 

## globalPermissionManager.py
Script to export ALL Global Permissions from a vCenter Server Appliance to an object file, and then re-import them as needed.

Needs to be run on a source/target vCenter.

============================================================= 

## fix_known_hosts.sh
Script to find any and all entries associated with a particular FQDN and IP and remove all entries associated with those from all known_hosts files in the SDDC Manager

Once they are deleted, we add newly computed keyscans values to the known_hosts files

============================================================= 

## sddcManagerVncaCert.py
Script to regenerate the SDDC Manager Certificate with a new VMCA (From MGMT vCenter) signed Certificate
