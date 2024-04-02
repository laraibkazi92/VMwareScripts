#!/usr/bin/env python

import requests
import subprocess
import sys
import os
import socket
import ssl
import getpass
import json
from shutil import move

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(parentdir)

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

OPENSSL = '/usr/bin/openssl'

__author__ = 'Laraib Kazi'

_DefaultCommmandEncoding = sys.getfilesystemencoding()


def openssl(*args):
    cmdline = [OPENSSL] + list(args)
    subprocess.check_call(cmdline,stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
                encoding=_DefaultCommmandEncoding, log_command=True):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    stdout, stderr = process.communicate(stdin)
    return stdout
    
def getMgmtVC():
    api_url = 'http://localhost/inventory/vcenters'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    vcenters = json.loads(response.text)
    for entry in vcenters:        
        if entry["domainType"] == "MANAGEMENT":
            return entry["hostName"]

def getHostname():
    #logger.debug("Getting hostname")
    cmd = ['/usr/bin/hostname', '-f']
    return run_command(cmd).decode().strip()

fqdn = getHostname()
mgmtVc = getMgmtVC()

def get_session_token(fqdn, username, password):

    api_url = f"https://{fqdn}/rest/com/vmware/cis/session"
    headers = {"Content-Type": "application/json"}

    response = requests.request("POST", api_url, auth=(username,password), headers=headers,verify=False)
    if response.status_code == 200:
        # print("\n Session token created successfully.\n")
        session_token = response.json()["value"]
        return session_token
    else:
        print("\n Failed to create session token.\n Please check entered credentials")
        print("Response:", response.text)
        sys.exit(1)

def sso_username():
    
    api_url = 'http://localhost/inventory/domains'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    # Setting default ssoName = vsphere.local
    ssoName=''
    try:
        for entry in json.loads(response.text):
            if entry["type"] == "MANAGEMENT":
                ssoName = (entry["ssoName"])
                break
    except:
        ssoName = 'vsphere.local'
    
    username = 'administrator@'+ssoName
    return username

def sso_prompt():
    print('\n')
    username = sso_username()
    sso_password = getpass.getpass('Provide password for %s: ' % username)
    return username,sso_password

def getSslCert(hostname,port):
    """
    Gets SSL cert from host on port specified. 
        
    Args:
        hostname (str): hostname
        port (int): port
    
    Returns:
        cert: certificate string formatted for lookup service endpoints
    """
    #  returns the cert trust value formatted for lstool
    # logger.debug("Getting SSL certificate on %s:%s" % (hostname, port))
    socket.setdefaulttimeout(5)
    try:
        try:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_TLS)
        
        except AttributeError:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_SSLv23)

        except socket.timeout as e:
            raise Exception("Timed out getting certificate")

        except ConnectionRefusedError:
            # print("Connection refused while getting cert for host %s on port %s!" % (hostname, port))
            raise
        
        return cert

    except Exception as e:
        msg = ("[%s:%s]:%s" 
                        % (hostname, port, str(e)))
        raise Exception(msg)

def createCsrConfig():
    # Creating CSR Config with Extensions  
    csrConfig=f'''[req]
default_bits = 4096
distinguished_name = dn
prompt             = no
req_extensions = req_ext

[dn]
C="US"
ST="CA"
L="PA"
O="VMware"
OU="VMware Engineering"
CN={fqdn}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.0 = {fqdn}
'''
    try:
        with open("/tmp/csrConfig.conf", 'w') as f:
            f.write(csrConfig)
        print('  > CSR config file created: /tmp/csrConfig.conf')
    except Exception as e:
        print(f'  !! Failed to create CSR config file.\n  Exception: {e}')
        sys.exit(1)        

def createCSR():
    
    createCsrConfig()
    sddcKey = '/tmp/'+fqdn+'.key'
    sddcCsr = '/tmp/'+fqdn+'.csr'
    csrConfig = '/tmp/csrConfig.conf'
    
    try:
        openssl('req', '-new', '-keyout', str(sddcKey), '-out', str(sddcCsr), '-config', str(csrConfig), '-nodes')
        print(f'  > CSR file created: {sddcCsr}')
        print(f'  > Key file created: {sddcKey}')
    except Exception as e:
        print(f'  !! Failed to generate CSR and Key files.\n  Exception: {e}')
        sys.exit(1)

def getVmcaSignedCert(session_token):
    
    sddcCrtFile = '/tmp/'+fqdn+'.crt'
    sddcCsrFile = '/tmp/'+fqdn+'.csr'
    
    createCSR()
    
    with open(sddcCsrFile, 'r') as f:
        sddcCsr = f.read()
        
    api_url = f'https://{mgmtVc}/rest/vcenter/certificate-authority/sign-cert?action=sign-cert-from-csr'
    headers = {'vmware-api-session-id': session_token}
    data = {"csr":sddcCsr.rstrip('\n')}
    try:
        response = requests.request('POST',api_url, headers=headers, json=data, verify=False)
        cert_output = response.json()["value"] 
        with open (sddcCrtFile, 'w') as f:
            f.write(cert_output)
        print(f'  > Certificate file created: {sddcCrtFile}')
    except Exception as e:
        print(f'  !! Failed to Certificate file.\n  Exception: {e}')
        sys.exit(1)   

def installCert():
    # Deploy the generated certificate & key in the correct directory
    sddcCrtFile = '/tmp/'+fqdn+'.crt'
    sddcKeyFile = '/tmp/'+fqdn+'.key'
    destinationCrt = '/etc/ssl/certs/vcf_https.crt'
    destinationKey = '/etc/ssl/private/vcf_https.key'
    
    try:
        move(sddcCrtFile, destinationCrt)
        move(sddcKeyFile, destinationKey)
        print(f'  > Certificate installed successfully')
    except Exception as e:
        print(f'  !! Failed to install certificate.\n  Exception: {e}')
        sys.exit(1)
        
    os.system('systemctl restart nginx')
    print(f'  > Nginx service restarted')
    
def workflowValidator(fqdn):
    # Check if Certificate is applied
    destinationCrt = '/etc/ssl/certs/vcf_https.crt'
    with open(destinationCrt, 'r') as f:
        localCert=load_certificate(FILETYPE_PEM, f.read())
    
    localCertFingerprint = localCert.digest("sha1")
    
    cert=getSslCert(fqdn,'443')
    serverCert=load_certificate(FILETYPE_PEM, cert)
    serverCertFingerprint = serverCert.digest("sha1")

    if(localCertFingerprint == serverCertFingerprint):
        print("\nSUCCESS : VMCA Signed Certificate has been applied to {}.\n\n".format(fqdn))
    else:
        print("\nERROR : Certificate validation failed.\nPlease validate the applied certificate manually .....\n\n")
    
def main(username, password):
    
    ValidOption = False
    print('\n ========================================= ')
    print(f'\n This workflow will replace the SDDC Manager certificate with a newly generated one\n signed by the VMCA of {mgmtVc}.')  
    print('\n ========================================= ')
    
    while ValidOption == False:
        option = input(f'\n Are you sure you want to proceed? (Y|y|N|n) : ')
        if option.lower() == 'y':
            ValidOption = True
        elif option.lower() == 'n':
            print(' Exiting ...\n')
            sys.exit(0)
        else:
            print(' Invalid option. Try again.\n')
        
    session_token = get_session_token(mgmtVc, username, password)
    getVmcaSignedCert(session_token)
    installCert()
    workflowValidator(fqdn)
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    else:
        username,password = sso_prompt()
        main(username,password)