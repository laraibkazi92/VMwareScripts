#!/usr/bin/env python

import requests
import json
import subprocess
import ssl
import argparse
import sys
import getpass
import socket
import logging
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = 'Laraib Kazi'
__version__ = '1.4.0'

logdir = '/var/log/vmware/'
logFile = logdir+'nsxtVmcaCert.log'
logging.basicConfig( filename = logFile,filemode = 'a',level = logging.DEBUG,format = '%(asctime)s [%(levelname)s]: %(message)s', datefmt = '%m/%d/%Y %I:%M:%S %p' )
logger = logging.getLogger(__name__)

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

def prompt():
    '''
    Prompts for password for admin
    '''
    # Get password with no echo
    passwd = getpass.getpass("Provide password for the NSX-T admin user: ")
    logger.info('admin password has been input.')
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
    logger.debug(f'Running command: {cmdline}')
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

def createCsr(fqdn,user,passwd,nsxtVersion):
    # API for CSR Request 
    try:
        if nsxtVersion < 312:
            logger.debug(f'NSX Version is < 312. Using legacy "csr" API.')
            csrConfig = createCsrConfig(fqdn)
            api_url = "https://{}/api/v1/trust-management/csrs".format(fqdn)
        else:
            logger.debug(f'NSX Version is > 312. Using new "csrs-extended" API.')
            csrConfig = createCsrConfigExt(fqdn)
            api_url = "https://{}/api/v1/trust-management/csrs-extended".format(fqdn)   
    except Exception as e:
        logger.error(f'Failed to create CSR Configuration. Error: {e}')   
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)  

    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    logger.info(f'Attempting POST API Call with URL {api_url}')
    response = requests.request("POST", api_url, auth=(user,passwd), headers=headers, data=json.dumps(csrConfig), verify=False)
    try:
        csr_text = json.loads(response.text)["pem_encoded"]
        csr_id = json.loads(response.text)["id"]
        logger.debug(f'CSR generated successfully. Raw CSR:\n{csr_text}')
        logger.debug(f'CSR ID:{csr_id}')
    except Exception as e:
        logger.error(f'Error generating CSR: {e}')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)

    with open(fqdn+".csr", 'w') as f:
        f.write(csr_text)
    logger.info(f'CSR written to file: {fqdn}.csr')
    
    print(" > CSR Created ... | CSR ID : "+csr_id)
    return csr_id

def createVmcaSignedCert(fqdn,user,passwd):
    
    ipaddr = socket.gethostbyname(fqdn)
    logger.info(f'IP Address for {fqdn}: {ipaddr}')
    
    OPENSSL_x509CONFIG = """subjectKeyIdentifier = hash
authorityKeyIdentifier=keyid,issuer
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName = DNS: {}
""".format(fqdn,ipaddr)

    with open('extfile.conf', 'w') as f:
        f.write(OPENSSL_x509CONFIG)
    logger.debug(f'openssl x509 config written to: "extfile.conf"')

    ca_cert_location = '/var/lib/vmware/vmca/root.cer'
    ca_key_location = '/var/lib/vmware/vmca/privatekey.pem'
    csr_location = fqdn+".csr"

    logger.info('Running openssl command to generate a VMCA signed certificate.')
    try:
        openssl('x509', '-req', '-extfile', 'extfile.conf', '-days', '730', '-in', str(csr_location), '-CA', str(ca_cert_location), '-CAkey', str(ca_key_location), '-CAcreateserial', '-out', str(fqdn+".leaf.crt"), '-sha256')
        logger.info('VMCA Signed Certifcate created succesfully.')
    except Exception as e:
        logger.error(f'openssl command to create certificate failed. Error: {e}')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)
        
    # Concatentating VMCA cert to Server Certificate file
    with open(fqdn+".leaf.crt", 'r') as f1:
        server_content = f1.read()
        logger.debug(f'Raw Certificate:\n{server_content}')
    with open("/var/lib/vmware/vmca/root.cer", 'r') as f2:
        ca_content = f2.read()
    logger.debug('Combining the VMCA root and Leaf certificate to one file.')
    chain_content = server_content + ca_content
    logger.debug(f'Raw Certificate Chain:\n{chain_content}')
    with open(fqdn+".crt", 'w') as f:
        f.write(chain_content)
    logger.debug(f'Certificate Chain written to: {fqdn}.crt')
    
    print(" > VMCA Signed Certificate for {} created ...".format(fqdn))

def importCertNSX(fqdn, csr_id,user,passwd):
    # Creating payload to import the certificate
    try:
        with open(fqdn+".crt", 'r') as f:
            cert_chain=f.read()
        logger.debug(f'Reading certificate chain from file: {fqdn}.crt')
    except Exception as e:
        logger.error(f'Failed to read certificate chain from file. Error: {e}')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)

    import_payload={ 
    "pem_encoded": cert_chain
}
    
    # Importing Certificate to NSX Cert Store
    api_url = "https://{}/api/v1/trust-management/csrs/{}?action=import".format(fqdn, csr_id)

    headers = {'Content-Type': 'application/json'}

    logger.info(f'Attempting POST API Call with URL {api_url}')
    response = requests.request("POST", api_url, auth=(user,passwd), headers=headers, data=json.dumps(import_payload), verify=False)
    try:
        output = json.dumps(json.loads(response.text)["results"])
        stripped_value=output.lstrip(output[0]).rstrip(output[-1])
        crt_id = json.loads(stripped_value)["id"]
        logger.info(f'Certificate imported successfully to NSX Manager. Certificate ID: {crt_id}')
        
    except Exception as e:
        logger.error(f'Failed to import certificate. Error: {e}')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)
    
    print(" > Certificate imported to {} ... | Certificate ID: {}".format(fqdn, crt_id))
    return crt_id

def applyCertNsxtManager(fqdn,crt_id,user,passwd,nodeId):
    # Apply Certificate to NSX-T Manager
    api_url = f"https://{fqdn}/api/v1/trust-management/certificates/{crt_id}?action=apply_certificate&service_type=API&node_id={nodeId}"
            
    logger.info(f'Attempting POST API Call with URL {api_url}')
    response = requests.request("POST", api_url, auth=(user,passwd), verify=False)
    if response.status_code == 200:
        print(" > Certificate applied to {} ...".format(fqdn))
        logger.info(f'Certificate applied successfully.')
    else:
        print(" !! Failed to apply certificate !!")
        logger.info(f'Failed to apply certificate.')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)

def applyCertNsxtVIP(fqdn,crt_id,user,passwd,nsxtVersion):
    # Apply Certificate to NSX-T VIP
    if nsxtVersion < 320:
        api_url = f"https://{fqdn}/api/v1/cluster/api-certificate?action=set_cluster_certificate&certificate_id={crt_id}"
    else:
        api_url = f"https://{fqdn}/api/v1/trust-management/certificates/{crt_id}?action=apply_certificate&service_type=MGMT_CLUSTER"
        
    logger.info(f'Attempting POST API Call with URL {api_url}')
    response = requests.request("POST", api_url, auth=(user,passwd), verify=False)
    if response.status_code == 200:
        print(" > Certificate applied to {} ...".format(fqdn))
        logger.info(f'Certificate applied successfully.')
    else:
        print(" !! Failed to apply certificate !!")
        logger.info(f'Failed to apply certificate.')
        logger.error(f'Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.')
        sys.exit(1)

def getManagerNodeId(fqdn,user,passwd):
    api_url = f"https://{fqdn}/api/v1/cluster"
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, auth=(user,passwd), verify=False)
    cluster_info = response.json()
    nodes = cluster_info["nodes"]
    
    required_nodeId = None
    for node in nodes:
        if fqdn == node["fqdn"]:
            required_nodeId = node["node_uuid"]
            logger.debug(f'Identified Node id for {fqdn}: {required_nodeId}')
            break        
    
    if required_nodeId is None:
        raise Exception
    else:
        return required_nodeId    

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
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, auth=(user,passwd), verify=False)
    try:
        output = json.dumps(json.loads(response.text)["node_version"])
        logger.debug(f'NSX Version from API: {output}')
        print(" > NSX-T Version Detected {} ...".format(output))
        shortOutput = output.split(".")
        shortVersion = int(shortOutput[0].replace('"','')+shortOutput[1]+shortOutput[2])
        return shortVersion
    except Exception as e:
        logger.error(f'Failed to get NSX Version. Error: {e}')
    
def main():

    args = GetArgs()
    passwd = prompt()

    fqdn = args.fqdn
    user = 'admin'

    # In case the API to get NSX Version fails
    # We give it a default value of 4.0.0
    try:
        nsxtVersion = nsxtVersionChecker(fqdn,user,passwd)
    except:
        nsxtVersion = 400
    logger.debug(f'NSX Version assigned: {nsxtVersion}')
    
    
    try:
        nodeId = getManagerNodeId(fqdn,user,passwd)
    except:
        logger.error("Failed to get node id. Please review the logs at /var/log/vmware/nsxtVmcaCert.log for details.")
        
    csrId = createCsr(fqdn,user,passwd,nsxtVersion)
    createVmcaSignedCert(fqdn,user,passwd)
    crtId = importCertNSX(fqdn,csrId,user,passwd)
    
    if args.manager:
        applyCertNsxtManager(fqdn,crtId,user,passwd,nodeId)
    elif args.vip:
        applyCertNsxtVIP(fqdn,crtId,user,passwd,nsxtVersion)
    else:
        print("No arguements specified.")
    
    workflowValidator(fqdn)
    sys.exit(0)

if __name__ == "__main__":
    main()
