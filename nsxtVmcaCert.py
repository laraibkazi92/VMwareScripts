#!/usr/bin/env python

import requests
import json
import subprocess
import ssl
import argparse
import sys
import getpass
import socket
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

'''
This script is to update NSX-T Node Certificates (Manager and VIP) to VMCA Signed Certificates.

The script HAS to be run on a PSC or an embedded VC.

The script will:
1) Generate a CSR using NSX-T API
2) Generate a VMCA-signed certificate on the VC
3) Import the certificate to the NSX-T Node
4) Apply the certificate to the NSX-T Node
5) Confirm the new certificate on the Node matches the locally created certificate thumbprint.

The script has to be re-run for each NSX-T node.
'''

OPENSSL = '/usr/bin/openssl'

__author__ = 'Laraib Kazi | @starlord'

def prompt():
    '''
    Prompts for password for admin
    '''
    # Get password with no echo
    passwd = getpass.getpass("Provide password for the NSX-T admin user: ")
    return passwd

def GetArgs():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(description='Provide the FQDN and select an option to replace either NSX-T Manager or NSX-T VIP Certificate \
                    \n | For example: python nsxtVmcaCert.py -f nsxt-1.gsslabs.com -m')
    parser.add_argument('-f', '--fqdn', action='store', required=True, help='FQDN of the node')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-m', '--manager', action='store_true', default=False, help='Replace the certificate of the NSX-T Manager')
    group.add_argument('-v', '--vip', action='store_true', default=False, help='Replace the certificate of the NSX-T VIP')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    return args

def openssl(*args):
    cmdline = [OPENSSL] + list(args)
    subprocess.check_call(cmdline,stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)

def createCsrConfigExt(fqdn):
    # Creating CSR Config with Extensions
    
    csrConfig={ 
    "subject": {
        "attributes": [
        {
            "key": "CN",
            "value": fqdn
        },
        {
            "key": "O",
            "value": "VMware"
        },
        {
            "key": "OU",
            "value": "VMware Engineering"
        },
        {
            "key": "C",
            "value": "US"
        },
        {
            "key": "ST",
            "value": "CA"
        },
        {
            "key": "L",
            "value": "PA"
        }
        ]
    },
    "key_size": "2048",
    "algorithm": "RSA",
    "extensions": {
        "subject_alt_names": {
        "dns_names": [
            fqdn
        ],
        "ip_addresses": [
           socket.gethostbyname(fqdn) 
        ]
        }
    }
}
    return csrConfig

def createCsrConfig(fqdn):
    # Creating CSR Config
    
    csrConfig={ 
    "subject": {
        "attributes": [
        {
            "key": "CN",
            "value": fqdn
        },
        {
            "key": "O",
            "value": "VMware"
        },
        {
            "key": "OU",
            "value": "VMware Engineering"
        },
        {
            "key": "C",
            "value": "US"
        },
        {
            "key": "ST",
            "value": "CA"
        },
        {
            "key": "L",
            "value": "PA"
        }
        ]
    },
    "key_size": "2048",
    "algorithm": "RSA"
}
    return csrConfig

def createCsr(fqdn,user,passwd):
    # API for CSR Request
    
    nsxtVersion = nsxtVersionChecker(fqdn,user,passwd)
    
    if nsxtVersion < 312:
        csrConfig = createCsrConfig(fqdn)
        api_url = "https://{}/api/v1/trust-management/csrs".format(fqdn)
    else:
        csrConfig = createCsrConfigExt(fqdn)
        api_url = "https://{}/api/v1/trust-management/csrs-extended".format(fqdn)        

    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    response = requests.request("POST", api_url, auth=(user,passwd), headers=headers, data=json.dumps(csrConfig), verify=False)
    csr_text = json.loads(response.text)["pem_encoded"]
    csr_id = json.loads(response.text)["id"]
    #print(csr_text)

    with open(fqdn+".csr", 'w') as f:
        f.write(csr_text)
    
    print(" > CSR Created ... | CSR ID : "+csr_id)
    return csr_id

def createVmcaSignedCert(fqdn,user,passwd):
    
    ipaddr = socket.gethostbyname(fqdn)
    
    OPENSSL_x509CONFIG = """subjectKeyIdentifier = hash
authorityKeyIdentifier=keyid,issuer
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName = DNS: {}
""".format(fqdn,ipaddr)

    with open('extfile.conf', 'w') as f:
        f.write(OPENSSL_x509CONFIG)

    ca_cert_location = '/var/lib/vmware/vmca/root.cer'
    ca_key_location = '/var/lib/vmware/vmca/privatekey.pem'
    csr_location = fqdn+".csr"

    openssl('x509', '-req', '-extfile', 'extfile.conf', '-days', '730', '-in', str(csr_location), '-CA', str(ca_cert_location), '-CAkey', str(ca_key_location), '-CAcreateserial', '-out', str(fqdn+".leaf.crt"), '-sha256')
    
    # Concatentating VMCA cert to Server Certificate file
    with open(fqdn+".leaf.crt", 'r') as f1:
        server_content = f1.read()
    with open("/var/lib/vmware/vmca/root.cer", 'r') as f2:
        ca_content = f2.read()
    chain_content = server_content + ca_content
    with open(fqdn+".crt", 'w') as f:
        f.write(chain_content)
    
    print(" > VMCA Signed Certificate for {} created ...".format(fqdn))

def importCertNSX(fqdn, csr_id,user,passwd):
    # Creating payload to import the certificate
    with open(fqdn+".crt", 'r') as f:
        cert_chain=f.read()

    import_payload={ 
    "pem_encoded": cert_chain
}
    
    # Importing Certificate to NSX Cert Store
    api_url = "https://{}/api/v1/trust-management/csrs/{}?action=import".format(fqdn, csr_id)

    headers = {'Content-Type': 'application/json'}

    response = requests.request("POST", api_url, auth=(user,passwd), headers=headers, data=json.dumps(import_payload), verify=False)
    output = json.dumps(json.loads(response.text)["results"])
    stripped_value=output.lstrip(output[0]).rstrip(output[-1])
    crt_id = json.loads(stripped_value)["id"]

    print(" > Certificate imported to {} ... | Certificate ID: {}".format(fqdn, crt_id))
    return crt_id

def applyCertNsxtManager(fqdn,crt_id,user,passwd):
    # Apply Certificate to NSX-T Manager
    api_url = "https://{}/api/v1/node/services/http?action=apply_certificate&certificate_id={}".format(fqdn, crt_id)
    response = requests.request("POST", api_url, auth=(user,passwd), verify=False)
    print(" > Certificate applied to {} ...".format(fqdn))

def applyCertNsxtVIP(fqdn,crt_id,user,passwd):
    # Apply Certificate to NSX-T VIP
    api_url = "https://{}/api/v1/cluster/api-certificate?action=set_cluster_certificate&certificate_id={}".format(fqdn, crt_id)
    response = requests.request("POST", api_url, auth=(user,passwd), verify=False)
    print(" > Certificate applied to {} ...".format(fqdn))

def workflowValidator(fqdn):
    # Check if Certificate is applied
    with open(fqdn+".crt", 'r') as f:
        localCert=load_certificate(FILETYPE_PEM, f.read())
    
    localCertFingerprint = localCert.digest("sha1")
    
    cert=ssl.get_server_certificate((fqdn, 443))
    serverCert=load_certificate(FILETYPE_PEM, cert)
    serverCertFingerprint = serverCert.digest("sha1")

    if(localCertFingerprint == serverCertFingerprint):
        print("\nSUCCESS : VMCA Signed Certificate has been applied to {}.\n\n".format(fqdn))
    else:
        print("\nERROR : Certificate validation failed.\nPlease validate the applied certificate manually .....\n\n")
        
def nsxtVersionChecker(fqdn,user,passwd):
    # Check NSX-T Version
    api_url = "https://{}/api/v1/node/version".format(fqdn)
    response = requests.request("GET", api_url, auth=(user,passwd), verify=False)
    output = json.dumps(json.loads(response.text)["node_version"])
    print(" > NSX-T Version Detected {} ...".format(output))
    
    shortOutput = output.split(".")
    shortVersion = int(shortOutput[0].replace('"','')+shortOutput[1]+shortOutput[2])
    return shortVersion

def main():

    args = GetArgs()
    passwd = prompt()

    fqdn = args.fqdn
    user = 'admin'

    csrId = createCsr(fqdn,user,passwd)
    createVmcaSignedCert(fqdn,user,passwd)
    crtId = importCertNSX(fqdn,csrId,user,passwd)
    
    if args.manager:
        applyCertNsxtManager(fqdn,crtId,user,passwd)
    elif args.vip:
        applyCertNsxtVIP(fqdn,crtId,user,passwd)
    else:
        print("No arguements specified.")
    
    workflowValidator(fqdn)
    sys.exit(0)

if __name__ == "__main__":
    main()
