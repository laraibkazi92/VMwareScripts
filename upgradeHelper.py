#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi"]
__credits__ = ["Tyler FitzGerald", "Sydney Young"]
__license__ = "SPDX-License-Identifier: MIT"
__status__ = "Beta"
__copyright__ = "Copyright (C) 2024 Broadcom Inc."

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import os
import sys
# Check if root user:
if os.geteuid() != 0:
    print('\nNon-root user detected. \nupgradeHelper requires root privileges. \nPlease change user to root and re-run this script.\n')
    sys.exit(1)

import json
import subprocess
import yaml
import requests
import logging
import urllib3
import getpass
import stat
import socket
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__author__ = 'Laraib Kazi'
__version__ = '3.1.5'

logdir = '/var/log/vmware/vcf/'
logFile = logdir+'upgradeHelper.log'
logging.basicConfig( filename = logFile,filemode = 'a',level = logging.DEBUG,format = '%(asctime)s [%(levelname)s]: %(message)s', datefmt = '%m/%d/%Y %I:%M:%S %p' )
logger = logging.getLogger(__name__)

'''
This script is to assist with VCF upgrades, namely checking the VersionAlias.yml configuration.

Pre-requistes:
- SDDC Manager has to be upgraded to the target VCF BoM.
- The script has to be run as root.

For any questions and concerns, please reach out to me directly at laraib.kazi@broadcom.com

This script is only intended for SDDC Manager 4.x and 5.x
It will not run on SDDC Manager 3.x
'''
CYELLOW = '\033[93m'
CGREEN = '\033[92m'
CRED = '\033[91m'
CBLUE = '\033[96m'
CEND = '\033[0m'

def title():
    head=f'''
                              _     _  _     _               
  _  _ _ __  __ _ _ _ __ _ __| |___| || |___| |_ __  ___ _ _ 
 | || | '_ \/ _` | '_/ _` / _` / -_) __ / -_) | '_ \/ -_) '_|
  \_,_| .__/\__, |_| \__,_\__,_\___|_||_\___|_| .__/\___|_|  
      |_|   |___/                             |_|            
=============================================================
                    {CBLUE}Version: {__version__}{CEND}

'''
    print(head)
    logger.info(f'-------------- Starting upgradeHelper version: {__version__} ------------------')
    
def prompt():
    username = input("Please provide SSO administrator user[administrator@vsphere.local]:")
    if not username:
        username = "administrator@vsphere.local"

    # Get password with no echo
    passwd = getpass.getpass("Provide password for %s: " % username)
    return username, passwd

def gen_token(sso_username, sso_password):
    header = {'Content-Type': 'application/json'}
    data = {"username": sso_username,"password": sso_password}
    api_type = "POST"
    api_url = "https://127.0.0.1/v1/tokens"
    logger.info(f'Attempting {api_type} API Call with URL {api_url}')
    apiResponse = requests.request(api_type,api_url,headers=header,data=json.dumps(data),verify=False)
    try:
        logger.debug(f'Access Token Acquired.')
        return(apiResponse.json()["accessToken"])
    except:
        logger.error(f'Failed to get Access Token: {apiResponse.text}')
        print(f'\n{CRED}Failed to get Access Token. Incorrect Credentials provided. Please try again.{CEND}\n')
        sys.exit(1)
        
def loadManifest(token):
    # Loads Manifest for Current version of SDDC Manager
    api_url = "https://localhost/v1/manifests"
    api_type = "GET"
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting {api_type} API Call with URL {api_url}')
    response = requests.request(api_type, api_url, headers=headers, verify=False)
    return response

def getAllBundles(token):
    """
    Get all bundles known to SDDC Manager.
    
    Args:
        token (str): Access token for the SDDC Manager API calls

    Returns:
        json: Output of all bundles details.
    """
    api_url = f'https://localhost/v1/bundles'
    api_type = "GET"
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting {api_type} API Call with URL {api_url}')
    response = requests.request(api_type, api_url, headers=headers, verify=False)
    if response.status_code == 200:
        logger.debug(f'Bundles: {response.json()["elements"]}')
        return response.json()['elements']
    else:
        # print(f"  [ {CRED}\u2717{CEND} ] {component} \tBundle: {bundleId} | Download Status: {CRED}Bundle Not Found{CEND}")
        logger.error(f'Server Error has occurred. Please review the lcm-debug.log')
        return 'null'

def getBundleValues(bundle):
    componentBundle = {'id':bundle['id'],
              'downloadStatus':bundle['downloadStatus'],
              'toVersion':bundle['components'][0]['toVersion'],
              'fromVersion':bundle['components'][0]['fromVersion'],
              'component':bundle['components'][0]['type']}
    
    downloadStatus = componentBundle['downloadStatus']
    component = componentBundle['component']
    if component == 'HOST':
        component = 'ESX_HOST'
    bundleId = componentBundle['id']
    
    if downloadStatus.lower() == 'successful':
        print(f"  [ {CGREEN}\u2713{CEND} ] {component} \tBundle: {bundleId} | Download Status: {CGREEN}{downloadStatus}{CEND}")    
    else:
        print(f"  [ {CYELLOW}!{CEND} ] {component} \tBundle: {bundleId} | Download Status: {CYELLOW}{downloadStatus}{CEND}")
    
    logger.debug(f'{component} Upgrade Bundle identified: {componentBundle}')   
    return componentBundle
     
def getRequiredBundles(targetVersion, token):
    allBundles = getAllBundles(token)
    vcBundle, nsxBundle,esxBundle = None, None, None
    print(f'\n{CBLUE}Checking Status of Required Upgrade Bundles:{CEND}\n')
    for bundle in allBundles:
        if nsxBundle==None:
            if (bundle['components'][0]['toVersion'] == targetVersion['nsx']) and (bundle['components'][0]['imageType'] == 'PATCH'):
                nsxBundle = getBundleValues(bundle)
                continue
        if vcBundle==None:
            if (bundle['components'][0]['toVersion'] == targetVersion['vc']) and (bundle['components'][0]['imageType'] == 'PATCH'):
                vcBundle = getBundleValues(bundle)                
                continue
        if esxBundle==None:
            if (bundle['components'][0]['toVersion'] == targetVersion['esx']) and (bundle['components'][0]['imageType'] == 'PATCH'):
                esxBundle = getBundleValues(bundle)
                continue
        if (vcBundle!=None) and (nsxBundle!=None) and (esxBundle!=None):
            break
    
    if nsxBundle == None:
        print(f"  [ {CRED}\u2717{CEND} ] NSX_T_MANAGER \tBundle: {CRED}Bundle Not Found{CEND}")
        logger.error(f'NSX_T_MANAGER Bundle not found. No Required Previous Version identified.')
    if vcBundle == None:
        print(f"  [ {CRED}\u2717{CEND} ] VCENTER \tBundle: {CRED}Bundle Not Found{CEND}")
        logger.error(f'VCENTER Bundle not found. No Required Previous Version identified.')
    if esxBundle == None:
        print(f"  [ {CRED}\u2717{CEND} ] ESX_HOST \tBundle: {CRED}Bundle Not Found{CEND}")
        logger.error(f'ESX_HOST Bundle not found. No Required Previous Version identified.')
    
    return {'vc':vcBundle, 'nsx':nsxBundle, 'esx':esxBundle}

def getTargetVersions(manifest,sddcVersion):
    
    response = manifest
    lcmData = response.json()['releases']
    # count = -1
    for entry in lcmData:
        # count = count + 1
        if entry['version'] == sddcVersion:
            # index = count
            for bomEntry in entry['bom']:
                if bomEntry['name'] == "NSX_T_MANAGER":
                    nsxtVersion=bomEntry['version']
                if bomEntry['name'] == "VCENTER":
                    vcVersion=bomEntry['version']
                if bomEntry['name'] == "HOST":
                    esxVersion=bomEntry['version']          
            targetManifestInfo = {"vc":vcVersion,"esx":esxVersion,"nsx":nsxtVersion}
            logger.debug(f'Manifest Info for Target BoM Version: {targetManifestInfo}')
            break
    return targetManifestInfo

def service_status():
    isLcmRunning = False
    isCommonSvcsRunning = False
    
    print(f'\n{CBLUE}Checking Status of Services:{CEND}\n')

    api_url = 'http://localhost/lcm/about'
    api_type = "GET"
    logger.info(f'Attempting {api_type} API Call with URL {api_url}')
    response = requests.request(api_type, api_url, verify=False)
    if response.status_code == 200:
        isLcmRunning = True
        logger.info('LCM Service is Active.')
        print(f"  [ {CGREEN}\u2713{CEND} ] LCM service is {CGREEN}ACTIVE{CEND}")
    else:
        logger.info('LCM Service is NOT Active.')
        print(f"  [ {CRED}\u2717{CEND} ] LCM service is {CRED}not ACTIVE{CEND}")
        
    api_url = 'http://localhost/commonsvcs/about'
    api_type = "GET"
    logger.info(f'Attempting {api_type} API Call with URL {api_url}')
    response = requests.request(api_type, api_url, verify=False)
    if response.status_code == 200:
        isCommonSvcsRunning = True
        logger.info('Commonsvcs Service is Active.')
        print(f"  [ {CGREEN}\u2713{CEND} ] CommonSvcs service is {CGREEN}ACTIVE{CEND}")
    else:
        logger.info('LCM Service is NOT Active.')
        print(f"  [ {CRED}\u2717{CEND} ] CommonSvcs service is {CRED}not ACTIVE{CEND}")
    
    if isLcmRunning == False or isCommonSvcsRunning == False:
        print(f'\nPlease make sure the service(s) are ACTIVE and Healthy and re-run script.\n') 
        logger.error(f'One or more services is not ACTIVE.') 
        return 1
    else:
        return 0
        
def permission_ownership_Check(IsVxRail):

    lcm_app_Path = "/opt/vmware/vcf/lcm/lcm-app/conf/"
    files_to_check1 = ["feature.properties","lcmManifest.json","VersionAlias.yml"]
    files_to_check2 = ["application-prod.properties","application.properties"]
    bundle_dir_Path = "/nfs/vmware/vcf/nfs-mount/bundle/"
    software_compatSet_file = "softwareCompatiblitySets.json"
    
    print(f'\n{CBLUE}Checking File Ownership and Permissions:{CEND}\n')
    
    # Checking ownership of files:
    all_files = files_to_check1 + files_to_check2
    checkPassed1 = True
    for file in all_files:
        try:
            path = Path(lcm_app_Path+file)
            logger.debug(f'Checking file ownership for : {path}')
            if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                checkPassed1 = False
                logger.debug(f'File Owner: {path.owner()} | File Group: {path.group()}')
                logger.error(f'Incorrect ownership : {lcm_app_Path+file}')
                print(f'  [ {CRED}\u2717{CEND} ] Incorrect ownership : {lcm_app_Path+file}')
        except Exception as e:
            logger.error(f'Failed to check file ownership for : {path}. Error: {e}')
    
    try:
        path = Path(bundle_dir_Path)
        logger.debug(f'Checking ownership for : {path}')
        if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                checkPassed1 = False
                logger.debug(f'Directory Owner: {path.owner()} | Directory Group: {path.group()}')
                logger.error(f'Incorrect ownership : {path}')
                print(f'  [ {CRED}\u2717{CEND} ] Incorrect ownership : {path}')
    except Exception as e:
        logger.error(f'Failed to check ownership for : {path}. Error: {e}')
    
    if IsVxRail == True:
        try:     
            path = Path(bundle_dir_Path+software_compatSet_file)
            logger.debug(f'Checking ownership for : {path}')
            if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                    checkPassed1 = False
                    logger.debug(f'File Owner: {path.owner()} | File Group: {path.group()}')
                    logger.error(f'Incorrect ownership : {path}')
                    print(f'  [ {CRED}\u2717{CEND} ] Incorrect ownership : {path}')
        except:
            logger.error(f'Cannot find {software_compatSet_file}')
    
    if checkPassed1 == False:
        logger.debug('File ownership check failed.')
        print(f'\n  Please update ownership for the above file(s) using the command: "chown vcf_lcm:lcm {CYELLOW}<filepath>{CEND}"\n')
    
    # Checking permissions of files:
    checkPassed2 = True
    for file in files_to_check1:
        try:
            logger.debug(f'Checking file permission for : {lcm_app_Path+file}')
            perms = oct(stat.S_IMODE(os.lstat(lcm_app_Path+file).st_mode))[-3:]
            if int(perms) < 600:
                checkPassed2 = False 
                logger.debug(f'File permissions : {str(perms)}')
                logger.error(f'Incorrect permissions : {lcm_app_Path+file}')
                print(f'  [ {CRED}\u2717{CEND} ] Incorrect permissions : {lcm_app_Path+file}')
        except:
            logger.error(f'Failed to check file permissions for : {path}. Error: {e}')
    
    try:
        logger.debug(f'Checking directory permission for : {bundle_dir_Path}')
        perms = oct(stat.S_IMODE(os.lstat(bundle_dir_Path).st_mode))[-3:]
        if int(perms) < 600:
                checkPassed2 = False
                logger.debug(f'Directory permissions : {str(perms)}')
                logger.error(f'Incorrect permissions : {bundle_dir_Path}')
                print(f'  [ {CRED}\u2717{CEND} ] Incorrect permissions : {bundle_dir_Path}')
    except Exception as e:
        logger.error(f'Failed to check directory permissions for : {path}. Error: {e}')
    
    if IsVxRail == True:                
        try:
            logger.debug(f'Checking file permission for : {bundle_dir_Path+software_compatSet_file}')
            perms = oct(stat.S_IMODE(os.lstat(bundle_dir_Path+software_compatSet_file).st_mode))[-3:]
            if int(perms) < 600:
                    checkPassed2 = False
                    logger.debug(f'File permissions : {str(perms)}')
                    logger.error(f'Incorrect permissions : {bundle_dir_Path+software_compatSet_file}')
                    print(f'  [ {CRED}\u2717{CEND} ] Incorrect permissions : {bundle_dir_Path+software_compatSet_file}') 
        except:
            logger.error(f'Cannot find {software_compatSet_file}')
    
    if checkPassed2 == False:
        logger.debug(f'File permission check failed for {files_to_check1}.')
        print(f'\n  Please update permissions for the above file(s) using the command: "chmod 600 {CYELLOW}<filepath>{CEND}"\n  NOTE: 600 is the minimum required permission.\n')
    
    checkPassed3 = True
    for file in files_to_check2:
        try:
            logger.debug(f'Checking file permission for : {lcm_app_Path+file}')
            perms = oct(stat.S_IMODE(os.lstat(lcm_app_Path+file).st_mode))[-3:]
            if int(perms) < 400:
                checkPassed3 = False
                logger.debug(f'File permissions : {str(perms)}')
                logger.error(f'Incorrect permissions : {lcm_app_Path+file}')
                print(f'  [ {CRED}\u2717{CEND} ] Incorrect permissions : {lcm_app_Path+file}')
        except Exception as e:
            logger.error(f'Failed to check file permissions for : {path}. Error: {e}')
    
    if checkPassed3 == False:
        logger.debug(f'File permission check failed for {files_to_check2}.')
        print(f'\n  Please update permissions for the above file(s) using the command: "chmod 400 {CYELLOW}<filepath>{CEND}"\n  NOTE: 400 is the minimum required permission.\n')
    
    if checkPassed1 == True and checkPassed2 == True and checkPassed3 == True:
        logger.info('File permissions and ownership check passed.')
        print(f"  [ {CGREEN}\u2713{CEND} ] File permissions and ownership are correct")
        return 0
    else:
        return 1
    
def checkMigrationFeatureFlags():
    filePath = '/home/vcf/feature.properties'
    try:
        with open(filePath, 'r') as f:
            features = f.read()
    except Exception as e:
        logger.error(f'Cannot read file: {filePath}. Error: {e}')
        return
    
    fail1 = False
    fail2 = False
    if "feature.lcm.store.target.version=false" in features:
        fail1 = True
    if "feature.vcf.isolated.wlds=false" in features:
        fail2 = True
    
    if fail1 is True or fail2 is True:
        print(f'\n{CBLUE}Checking Migration Feature Flags:{CEND}\n')
        if fail1 is True:
            print(f'  [ {CRED}\u2717{CEND} ] Found feature flag: feature.lcm.store.target.version=false')
        if fail2 is True:
            print(f'  [ {CRED}\u2717{CEND} ] Found feature flag: feature.vcf.isolated.wlds=false')
        print(f'\n  Please delete the above line(s) from the file "/home/vcf/feature.properties" and restart all services.') 
        

def checkDepotSettings(token, IsVxRail):
    
    print(f'\n{CBLUE}Checking Depot Configuration::{CEND}\n')
    
    print(f' DEPOT CONFIGURATION:')
    # Get current depot settings
    api_url = f'http://localhost/v1/system/settings/depot'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    try:    
        response.json()["vmwareAccount"]["status"] == "DEPOT_CONNECTION_SUCCESSFUL"
        print(f'  [ {CGREEN}\u2713{CEND} ] VMware depot connected successfully with user: {response.json()["vmwareAccount"]["username"]}')
        logger.info(f'VMware depot connected successfully with user: {response.json()["vmwareAccount"]["username"]}')
    except Exception as e:
        print(f"  [ {CRED}!{CEND} ] VMware depot is not connected")
        logger.error(f'VMware depot not connected. Error: {e}')
        
    if IsVxRail:
        try:    
            response.json()["dellEmcSupportAccount"]["status"] == "DEPOT_CONNECTION_SUCCESSFUL"
            print(f'  [ {CGREEN}\u2713{CEND} ] Dell depot connected successfully with user: {response.json()["dellEmcSupportAccount"]["username"]}')
            logger.info(f'VMware depot connected successfully with user: {response.json()["dellEmcSupportAccount"]["username"]}')
        except Exception as e:
            print(f"  [ {CRED}!{CEND} ] Dell depot is not connected")
            logger.error(f'VMware depot not connected. Error: {e}')

    depotConnectityTest(IsVxRail)
    proxyStatus(token)

def depotConnectityTest(IsVxRail):
    vmwareDepotUri = 'depot.vmware.com'
    dellDepotUri = 'colu.emc.com'
    port = 443
    timeout = 2
    print(f'\n CONNECTIVITY TEST:')
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((vmwareDepotUri, port))
        print(f'  [ {CGREEN}\u2713{CEND} ] Connectivity to VMware Depot is allowed')
        logger.info('Connectivity to VMware Depot allowed')
        IsVmwareAccess = True
    except socket.error as ex:
        print(f'  [ {CRED}!{CEND} ] Unable to connect to VMware Depot')
        logger.error('Unable to connect to VMware Depot')
        IsVmwareAccess = False
        
    if IsVxRail:
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((dellDepotUri, port))
            print(f'  [ {CGREEN}\u2713{CEND} ] Connectivity to Dell Depot is allowed')
            logger.info('Connectivity to Dell Depot allowed')
            IsDellAccess = True
        except socket.error as ex:
            print(f'  [ {CRED}!{CEND} ] Unable to connect to Dell Depot')
            logger.error('Unable to connect to Dell Depot')
            IsDellAccess = False
    
    print('')
    if IsVxRail:
        if (IsDellAccess == False) and (IsVmwareAccess == False):
            print(f'  [ {CRED}!{CEND} ] Environment Type may be {CRED}OFFLINE{CEND}')
        else:
            print(f'  [ {CGREEN}\u2713{CEND} ] Environment Type is ONLINE')
    else:
        if (IsVmwareAccess == False):
            print(f'  [ {CRED}!{CEND} ] Environment Type may be {CRED}OFFLINE{CEND}')
        else:
            print(f'  [ {CGREEN}\u2713{CEND} ] Environment Type is ONLINE')

def proxyStatus(token):
    print(f'\n PROXY:')
    api_url = f'http://localhost/v1/system/proxy-configuration'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    try:
        if response.json()["isConfigured"] == False:
            print(f'  [ {CGREEN}\u2713{CEND} ] No Proxy configured for LCM service in SDDC Manager')
            logger.info('Proxy not configured for LCM.')
        else:
            print(f'  [ {CRED}!{CEND} ] Proxy configured for LCM service in SDDC Manager. Host: {response.json()["host"]}')
            logger.info('Proxy configured for LCM.')
            if response.json()["isEnabled"] == False:
                print(f'  [ {CRED}!{CEND} ] Proxy is NOT enabled')
                logger.info('Proxy is NOT enabled.')
            else:
                print(f'  [ {CRED}!{CEND} ] Proxy is enabled')
                logger.info('Proxy is enabled.')
    except Exception as e:
        logger.error('proxy-configuration API failed to run.')            

def asyncPatching_Check():
    # Check if Async Patching is currently enabled in the environment
    
    print(f'\n{CBLUE}Checking Async Patching enabled:{CEND}\n')
    
    # Checking config in each file:
    def checkConfig(file, config):
        logger.debug(f'Reading file: {file}')
        try:
            with open(file) as f:
                fileContents = f.read()
            
            if config in fileContents:
                logger.debug(f'Config:{config} found in file: {file}')
                return True
            else:
                logger.debug(f'Config:{config} not found in file: {file}')
        except Exception as e:
            logger.error(f'Failed to open file. Error: {e}')
    
    # Files to check for Async Patch Configuration
    #file1 = '/opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties'
    file2 = '/opt/vmware/vcf/sddc-manager-ui-app/server/support/config.properties'
    
    # Config entries to check
    #config1 = 'lcm.depot.adapter.enableBundleSignatureValidation=true'
    config2 = 'enableVCFVersionBasedUpdate=false'
    
    asyncConfig = False
    
    if checkConfig(file2,config2) == True:
        asyncConfig = True

    if asyncConfig == True:
        print(f'  [ {CRED}\u2717{CEND} ] Async Patching configuration detected ')
        print('\tPlease disable Async Patching using the command: ')
        print(f'\t{CBLUE}/home/vcf/asyncPatchTool/bin/vcf-async-patch-tool --disableAllPatches --sddcSSOUser administrator@vsphere.local --sddcSSHUser vcf{CEND}\n')
        return 1
    else:
        print(f'  [ {CGREEN}\u2713{CEND} ] Async Patching configuration not detected')
        return 0
         
def getManifestPolling():
    print(f'\n{CBLUE}Checking LCM Manifest Polling status:{CEND}\n')
    try:
        with open('/opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties') as f:
            lines = f.readlines()
            for row in lines:
                if 'lcm.core.enableManifestPolling' in row:
                    if 'true' in row:
                        logger.debug('LCM Manifest Polling is Enabled')
                        print(f'  [ {CGREEN}\u2713{CEND} ] LCM Manifest Polling is Enabled')
                    else:
                        logger.debug('LCM Manifest Polling is NOT Enabled')
                        print(f'  [ {CRED}\u2717{CEND} ] LCM Manifest Polling is NOT Enabled')
    except Exception as e:
        logger.error(f'Failed to run manifest polling check. Error: {e}')
        
def getSDDCVersion():
    # Current SDDC Manager version:
    api_url = f'http://localhost/inventory/sddcmanagercontrollers'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    element = json.loads(response.text)[0]
    logger.debug(f'Found SDDC Manager element : {element}')
    sddcVersion = element['version'].split("-")[0]
    
    print(f"\n{CBLUE}SDDC Manager Version:{CEND}\n")
    print("  SDDC Manager: {}".format(sddcVersion))
    
    return sddcVersion
            
def getBoMVersionsFromAPI(domainId): 
    
    # Getting vCenter Info
    vcenter=[]
    api_url = f'http://localhost/inventory/vcenters'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    for element in json.loads(response.text):
        if element['domainId'] == domainId: 
            logger.debug(f'Found VCENTER element : {element}')
            vcenter.extend((element['id'], element['hostName'], element['version'], element['status']))
            break
    
    # Getting NSXT Info
    nsxt=[]        
    api_url = f'http://localhost/inventory/nsxt'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    for element in json.loads(response.text):
        if domainId in element['domainIds']:
            logger.debug(f'Found NSX element : {element}')
            nsxt.extend((element['id'], element['clusterFqdn'], element['version'], element['status']))
            break

    # Getting Host Info
    host=[]
    api_url = f'http://localhost/inventory/hosts'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    for element in json.loads(response.text):
        try:
            if element['domainId'] == domainId:
                logger.debug(f'Found ESX element : {element}')
                entry=[]
                entry.extend((element['id'], element['hostName'], element['version'], element['status']))
                host.append(entry)  
        except Exception as e:
            logger.error(f'Host likely not part of a domain. Error: {e}')      
    
    return vcenter,nsxt,host

def loadVersionAlias(component,token):
    api_url = "https://localhost/v1/system/settings/version-aliases"
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    
    try:
        vaEntries = response.json()["elements"]
        logger.debug(f'Version Alias Entries: {vaEntries}')
    except:
        logger.error(f'Error parsing Version Alias Entries via API. Error: {response.text}')
        return "error"
    
    try:
        for entry in vaEntries:
            if entry['bundleComponentType'] == component:
                logger.debug(f'For component {component} - versionAliases = {entry["versionAliases"]}')
                return entry['versionAliases']
    except Exception as e:
        logger.error(f'Error: {e}')
        return "None"

def hostStatusCheck(host):
    # Check the status of all hosts for a WLD
    isActive = True
    notActiveHosts = []
    for entry in host:
        if entry[3].lower() != 'active':
            logger.debug(f'Host not Active: {entry}')
            notActiveHosts.append(entry)
            isActive = False
    
    return notActiveHosts, isActive
        
def bundleAvailabilityLogic(requiredBundles,manifestTargetVersion,vcenter,nsxt,host,sddcVersion,token,IsVxRail):
    # Get current version of NSX-T, VC and ESXi for chosen domain

    # Version is the 2nd value
    version = 2
    # Status is the 4rd value
    status = 3
    
    logger.info('Printing Current Versions Detected.')
    print(f"\n{CBLUE}Current Versions Detected:{CEND}\n")
    print("  NSX-T: {}".format(nsxt[version]))
    print("  vCenter: {}".format(vcenter[version]))
    print("  ESXi: {}".format(host[0][version]))
    
    print(f"\n  Using VCF {sddcVersion} as the Target VCF BoM.")
    
    logger.info('Checking Status of Products')
    print(f"\n{CBLUE}Current Status Detected:{CEND}\n")
    statusChecker("NSX_T_MANAGER", nsxt[status])
    statusChecker("VCENTER", vcenter[status])
    
    notActiveHosts, isActive = hostStatusCheck(host)
    if isActive == True:
        statusChecker("ESX_HOST", 'ACTIVE')
    else:
        statusChecker("ESX_HOST", 'NotActive')
        print(f'  Following hosts are currently not in ACTIVE state: ')
        for host in notActiveHosts:
            print(f'    - {host[0]} | {host[1]}')
    
    # Perform Version Alias Configuration check
    logger.info(f'Performing Version Alias Checks.')
    print(f"\n{CBLUE}Version Alias Detection:{CEND} ")
    aliasChecker("NSX_T_MANAGER", manifestTargetVersion["nsx"], nsxt[version], requiredBundles['nsx'], sddcVersion, token)
    aliasChecker("VCENTER", manifestTargetVersion["vc"], vcenter[version], requiredBundles['vc'], sddcVersion, token)
    aliasChecker("ESX_HOST", manifestTargetVersion["esx"], host[0][version], requiredBundles['esx'], sddcVersion, token)
    
    # Skip compatibility set check if VCF = 5.x due to new VVS data:
    if sddcVersion.startswith('4.'):    
        # Check compatibility set validity only if VxRail Environement:
        logger.debug(f'SDDC Manager version is {sddcVersion}.')
        logger.info(f'Checking for presence of VxRail.')
        if IsVxRail == True:
            print(f"\n{CBLUE}VxRail Environment detected.\nCompatibility Sets Detection:{CEND}\n")
            logger.info(f'VxRail Environment - Checking compatibility sets.')
            compatSetError = compatSetChecker(requiredBundles)
            if compatSetError == False:
                logger.debug(f'VxRail Environment - Checking compatibility sets.')
                print(f"\n  [ {CGREEN}\u2713{CEND} ] Required Compatibility Sets found.")

def vxrailChecker():
    # Function to check if we have any VxRail Managers in the System i.e if this is a VxRail Environment
    
    api_url = f'http://localhost/inventory/vxmanagers'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)

    if response.text == '[]':
        logger.info(f'No VxRail Managers detected.')
        return False
    else:
        logger.info(f'VxRail Managers detected.')
        return True

def compatSetChecker(requiredBundles):
    ## TODO: Need to update function to use API to query scs
    ## Currently using a manual DB query, even though its faster
    # Function to check if we have valid Compatibility Sets for the bundle availability
    
    p = subprocess.Popen('psql -U postgres -h localhost -d lcm -qAtX -c "SELECT json from compatibility_set;"',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,shell=True)
    output,error = p.communicate()
    logger.debug(f'Compat Set psql output:\n{output}')
    logger.debug(f'Compat Set psql error:\n{error}')
    
    foundCompatSets = []
    for line in output.split("\n"):
        if line != '\n' and line != "":
            foundCompatSets.append(json.loads(line))
    
    logger.debug(f'All Compatibility Sets found:\n{foundCompatSets}')
    
    requiredSet1 = {"vc":{"version":requiredBundles['vc']['fromVersion']},
                    "esxi":{"version":requiredBundles['esx']['fromVersion']},
                    "nsxT":{"version":requiredBundles['nsx']['toVersion']},
                    'compatibilitySetVersion': 2}
    requiredSet2 = {"vc":{"version":requiredBundles['vc']['toVersion']},
                    "esxi":{"version":requiredBundles['esx']['fromVersion']},
                    "nsxT":{"version":requiredBundles['nsx']['toVersion']},
                    'compatibilitySetVersion': 2}
    requiredSet3 = {"vc":{"version":requiredBundles["vc"]['toVersion']},
                    "esxi":{"version":requiredBundles['esx']['toVersion']},
                    "nsxT":{"version":requiredBundles['nsx']['toVersion']},
                    'compatibilitySetVersion': 2}
    requiredCompatSets = [requiredSet1, requiredSet2, requiredSet3]
    
    logger.debug(f'Require Compatibility Sets based on Current and Previous Versions:\n{requiredCompatSets}')
    
    compatSetError = False
    for element in requiredCompatSets:
        if element not in foundCompatSets:
            logger.error(f'Required set: {element} is not found in the compatibilitySets.')
            print(f"  [ {CRED}\u2717{CEND} ] Required set: {element} is not found in the compatibilitySets.")
            compatSetError = True
    
    return compatSetError

def statusChecker(component, status):
    
    logger.debug(f'Component {component} has status {status}')
    if status == "ACTIVE":
        print(f"  [ {CGREEN}\u2713{CEND} ] {component} \t: {CGREEN}ACTIVE{CEND}")
    else:
        print(f"  [ {CRED}\u2717{CEND} ] {component} \t: {CRED}{status}{CEND} -> Please investigate the status of the component and mark as ACTIVE from the database if required.")
    
def aliasChecker(component, manifestTargetVersion, dbVersion, requiredVersions, sddcVersion, token):
    
    AliasCheck = False
    aliasFound = 0
    print(f"\n {component}:")
    
    logger.debug(f'Component: {component}')
    logger.debug(f'Current Version from DB: {dbVersion}')
    logger.debug(f'Manifest Target Version: {manifestTargetVersion}')
    logger.debug(f'SDDC Manager Version: {sddcVersion}')
    
    # Getting specific build numbers
    dbVersion_build = int(dbVersion.split("-")[1])
    manifestTargetVersion_build = int(manifestTargetVersion.split("-")[1])
    
    if dbVersion == manifestTargetVersion:
        # Check if the versions match current SDDC Version BOM
        logger.debug(f'Current Version from DB: {dbVersion} MATCHES Manifest Target Version: {manifestTargetVersion}. Component is already on target version. No aliasing required.')
        print(f"\n  [ {CGREEN}\u2713{CEND} ] {component} {dbVersion} is already on VCF {sddcVersion} BoM. No aliasing required.")
    else:
        try:
            if dbVersion_build > manifestTargetVersion_build:
                targetVersion = 'N/A'
                baseVersion = requiredVersions['toVersion'] 
                print(f"  [ {CYELLOW}!{CEND} ] {component} version {dbVersion} is a higher build than VCF {sddcVersion} BoM {component} version {baseVersion}.")
            else:    
                targetVersion = requiredVersions['toVersion']
                baseVersion = requiredVersions['fromVersion']
        except:
            logger.error(f'Alias Check failed for component {component}. No upgrade bundle found for product {component} in VCF BoM {sddcVersion}')
            print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}Alias checking failed. Upgrade Bundle not found for product {component}{CEND}.")
            return None
            
        logger.debug(f'Target Version from Required Bundle: {targetVersion}')
        logger.debug(f'Manifest Required Previous Version: {baseVersion}')
        
        # Get Version Aliasing for component
        vaEntries = loadVersionAlias(component,token)
        if vaEntries == "error":
            print(f"\n  {CRED}Error loading VersionAlias.yml file.{CEND} Please check the file for configuration/syntax errors.")
            sys.exit(1)
        elif vaEntries == "None" or vaEntries == None:
            print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}No entry found for {component} in VersionAlias.yml file.{CEND}")
            print(f"  Please add an entry for {component} with alias version {dbVersion} and base version {baseVersion}.")
        else:
            try:
                for entry in vaEntries:
                    for aliasEntry in entry['aliases']:
                        if aliasEntry == dbVersion:
                            aliasFound += 1
                            logger.debug(f'Alias Entry: {aliasEntry} MATCHES Current Version from DB: {dbVersion}. Updating aliasFound to {aliasFound}')
                            if entry['version'] == baseVersion:
                                logger.debug(f'Base Entry: {entry["version"]} MATCHES Manifest Required Previous Version: {baseVersion}. AliasCheck marked as True.')
                                AliasCheck = True
                            break
                if AliasCheck is True:
                    logger.debug(f'Correct Aliasing Found | Component version {dbVersion} MATCHES Manifest Required Previous Version: {baseVersion}.')
                    print(f"\n  [ {CGREEN}\u2713{CEND} ] {CGREEN}CORRECT ALIAS FOUND{CEND}: Current Version of {component} {dbVersion} is aliased to base version {baseVersion}.")
                elif aliasFound > 0:
                    logger.debug(f'Alias Found, required baseVersion not found. | Base Entry DOES NOT MATCH Manifest Required Previous Version: {baseVersion}. Need to update aliasing to correct base version: {baseVersion}.')
                    print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}INCORRECT BASE VERSION{CEND}: Current Version of {component} {dbVersion} is aliased to an INCORRECT base version.\n  Please edit the base version to {baseVersion}.")
                else:
                    logger.debug(f'No Alias Entry found. | Need to ADD an alias entry for {dbVersion} to correct base version: {baseVersion}.')
                    print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}NO ALIAS FOUND{CEND} for Current Version of {component} {dbVersion}.\n  Please add an alias for version {dbVersion} with base version as {baseVersion}.")
                
                if aliasFound > 1:
                    logger.debug(f'Multiple base versions detected for alias entry: {dbVersion}. Need to update aliasing to only correct base version: {baseVersion}.')
                    print(f"\n  [ {CRED}!!{CEND} ] Current Version of {component} {dbVersion} is being aliased to multiple base versions.\n  Please only alias it to base version {baseVersion}.")
            except Exception as e:
                logger.error(f'Fatal Exception: {e}')
                print(f'Unknown Exception. Please review logs at /var/log/vmware/vcf/upgradeHelper.log for additional details.')
                sys.exit(1)
        # Check what file has the allowed versions for aliasing
        aliasVersionAllowed(baseVersion, dbVersion, sddcVersion)

def loadVersionAliasYml():
    versionAliasFilePath = "/opt/vmware/vcf/lcm/lcm-app/conf/VersionAlias.yml"
    try:
        with open(versionAliasFilePath,"r") as f:
            vaYaml = yaml.safe_load(f)['allowedBaseVersionsForAliasing']
            logger.debug(f'Reading File: {versionAliasFilePath}')
            logger.debug(f'Version Aliases as yaml : {vaYaml}')
    except Exception as e:
        logger.error(f'Error: {e}')
        return "error"
    
    try:
        return vaYaml
    except:
        logger.error(f'Error: {e}')
        return "None"

def aliasVersionAllowed(baseVersion, dbVersion, sddcVersion):
    # Function to check if the versions are allowed to be aliased in the 
    # application.properties or application-prod.properties or VersionAlias.yml files
    
    # Coverting SDDC Version to an int value
    sddcVersion = int(sddcVersion.replace('.',''))

    lcmAppConfLocation = "/opt/vmware/vcf/lcm/lcm-app/conf/"
   
    allowedInVersionAlias = False
    allowedInAppProp = False
    allowedInAppProdProp = False
    
    if sddcVersion > 4500:
        logger.debug(f'SDDC Manager version is: {str(sddcVersion)}, i.e greater than 4500.')
        # Check if 'allowedBaseVersionsForAliasing' exists in VersionAlias.yml file:
        if 'allowedBaseVersionsForAliasing' in open(lcmAppConfLocation+"VersionAlias.yml").read():
            logger.debug(f'Entry "allowedBaseVersionsForAliasing" found in {lcmAppConfLocation}VersionAlias.yml .')
            allowedInVersionAlias = True
    else:
        logger.debug(f'SDDC Manager version is: {str(sddcVersion)}, i.e under 4500.')
        # Check if 'allowed.base.versions.for.aliasing' exists in application.properties file:
        if 'allowed.base.versions.for.aliasing' in open(lcmAppConfLocation+"application.properties").read():
            logger.debug(f'Entry "allowed.base.versions.for.aliasing" found in {lcmAppConfLocation}application.properties .')
            allowedInAppProp = True            
        
        # Check if 'allowed.base.versions.for.aliasing' exists in application-prod.properties file:
        if 'allowed.base.versions.for.aliasing' in open(lcmAppConfLocation+"application-prod.properties").read():
            logger.debug(f'Entry "allowed.base.versions.for.aliasing" found in {lcmAppConfLocation}application-prod.properties .')
            allowedInAppProdProp = True            
        
    
    def printVersionAllowedInfo(version, filename, exists):
        # This function prints the output of findings if the versions are allowed to be aliased
        # depending on the file that info is found in
        if exists==True:
            print(f"\n  [ {CGREEN}\u2713{CEND} ] Version {version} is allowed to be aliased in the {filename} file.")
            logger.debug(f'Version {version} is allowed to be aliased in the {filename} file.')
        else:
            print(f"\n  [ {CRED}\u2717{CEND} ] Version {version} is not allowed to be aliased in the {filename} file.")
            logger.debug(f'Version {version} is not allowed to be aliased in the {filename} file.')

    # Checking if version is allowed to be aliased as per priority of files:
    exists = False
    baseExists = False
    aliasExists = False
    
    if allowedInVersionAlias == True:
        vaAllowedList = loadVersionAliasYml()
        for entry in vaAllowedList:
            if baseVersion in entry:
                logger.info(f'{baseVersion} found in {lcmAppConfLocation}VersionAlias.yml .')
                baseExists = True
                printVersionAllowedInfo(baseVersion,"VersionAlias.yml",baseExists)                
            if dbVersion in entry:
                logger.info(f'{dbVersion} found in {lcmAppConfLocation}VersionAlias.yml .')
                aliasExists = True
                printVersionAllowedInfo(dbVersion,"VersionAlias.yml",aliasExists)
        if (aliasExists == True) and (baseExists == True):
            exists = True
        else:
            if baseExists == False:
                printVersionAllowedInfo(baseVersion,"VersionAlias.yml",baseExists)
            if aliasExists == False:
                printVersionAllowedInfo(baseVersion,"VersionAlias.yml",aliasExists)
                                
    elif allowedInAppProp == True:
        with open(lcmAppConfLocation+"application.properties") as f:
            for line in f:
                if 'allowed.base.versions.for.aliasing' in line:
                    if baseVersion in line:
                        logger.info(f'{baseVersion} found in {lcmAppConfLocation}application.properties .')
                        baseExists = True
                        printVersionAllowedInfo(baseVersion,"application.properties",baseExists)                        
                    if dbVersion in line:
                        logger.info(f'{dbVersion} found in {lcmAppConfLocation}application.properties .')
                        aliasExists = True
                        printVersionAllowedInfo(dbVersion,"application.properties",aliasExists)                        
                    break
            if (aliasExists == True) and (baseExists == True):
                exists = True
            else:
                if baseExists == False:
                    printVersionAllowedInfo(baseVersion,"application.properties",baseExists)
                if aliasExists == False:
                    printVersionAllowedInfo(baseVersion,"application.properties",aliasExists)                        
                    
    elif allowedInAppProdProp == True:
        with open(lcmAppConfLocation+"application-prod.properties") as f:
            for line in f:
                if 'allowed.base.versions.for.aliasing' in line:
                    if baseVersion in line:
                        logger.info(f'{baseVersion} found in {lcmAppConfLocation}application-prod.properties .')
                        baseExists = True
                        printVersionAllowedInfo(baseVersion,"application-prod.properties",exists)
                    if dbVersion in line:
                        logger.info(f'{dbVersion} found in {lcmAppConfLocation}application-prod.properties .')
                        aliasExists = True
                        printVersionAllowedInfo(dbVersion,"application-prod.properties",exists)
                    break
            if (aliasExists == True) and (baseExists == True):
                exists = True
            else:
                if baseExists == False:
                    printVersionAllowedInfo(baseVersion,"application-prod.properties",baseExists)
                if aliasExists == False:
                    printVersionAllowedInfo(baseVersion,"application-prod.properties",aliasExists)
    
    if exists == False:
        if sddcVersion > 4500:
            if allowedInVersionAlias == True:
                print(f'  Please edit the {lcmAppConfLocation}VersionAlias.yml file and add the following entry under "allowedBaseVersionsForAliasing":\n  (Append versions for other components as needed)')
                if baseExists == False:
                    print(f' - {baseVersion}')
                    logger.debug(f'Add {baseVersion} to {lcmAppConfLocation}VersionAlias.yml .')
                if aliasExists == False:
                    print(f' - {dbVersion}')
                    logger.debug(f'Add {dbVersion} to {lcmAppConfLocation}VersionAlias.yml .')
            else:
                print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}No entry found for allowing the base version to be aliased.{CEND}")
                print(f'  Please edit the {lcmAppConfLocation}VersionAlias.yml file and add the following entry at the top of the VersionAlias.yml file:\n  (Append ONLY versions for other components as needed)')
                print(f'\n  allowedBaseVersionsForAliasing:')
                if baseExists == False:
                    print(f' - {baseVersion}')
                    logger.debug(f'Add {baseVersion} to {lcmAppConfLocation}VersionAlias.yml .')
                if aliasExists == False:
                    print(f' - {dbVersion}')
                    logger.debug(f'Add {dbVersion} to {lcmAppConfLocation}VersionAlias.yml .')
        else:
            if allowedInAppProp == True:
                print(f'  Please edit the {lcmAppConfLocation}application.properties file and add the following version in the entry for "allowed.base.versions.for.aliasing":\n  (Append versions for other components as needed)')
                if baseExists == False:
                    print(f' {baseVersion}')
                    logger.debug(f'Add {baseVersion} to {lcmAppConfLocation}application.properties .')
                if aliasExists == False:
                    print(f' {dbVersion}')
                    logger.debug(f'Add {dbVersion} to {lcmAppConfLocation}application.properties .')
            elif allowedInAppProdProp == True:
                print(f'  Please edit the {lcmAppConfLocation}application-prod.properties file and add the following version in the entry for "allowed.base.versions.for.aliasing":\n  (Append versions for other components as needed)')
                if baseExists == False:
                    print(f' {baseVersion}')
                    logger.debug(f'Add {baseVersion} to {lcmAppConfLocation}application-prod.properties .')
                if aliasExists == False:
                    print(f' {dbVersion}')
                    logger.debug(f'Add {dbVersion} to {lcmAppConfLocation}application.properties .')
            else:
                print(f"\n  [ {CRED}\u2717{CEND} ] {CRED}No entry found for allowing the base version to be aliased.{CEND}")
                print(f'  Please edit the {lcmAppConfLocation}application-prod.properties file and add the following entry at the bottom of the file:\n  (Append ONLY versions for other components as needed)')
                print(f"\n  allowed.base.versions.for.aliasing=<version1>,<version2>")
                if baseExists == False:
                    print(f'  {baseVersion}')
                    logger.debug(f'Add {baseVersion} to {lcmAppConfLocation}application-prod.properties .')
                if aliasExists == False:
                    print(f'  {dbVersion}')
                    logger.debug(f'Add {dbVersion} to {lcmAppConfLocation}application-prod.properties .')

def domainSelector():
    # Getting Domain Info
    api_url = "http://localhost/inventory/domains"
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    logger.debug(f'Found Domains:\n{json.loads(response.text)}')
    domains=[]
    for element in json.loads(response.text):
        entry=[]
        entry.extend((element['id'], element['name'], element['type'], element['status']))
        domains.append(entry)

    print(f"\n{CBLUE}VCF Domains found:{CEND}")
    count = -1
    for element in domains:
        count = count + 1
        domainChoice = (f'[{str(count)}] {element[0]} | {element[1]} | {element[2]} | {element[3]}')
        print(domainChoice)
        logger.info(f'Domain Choice: {domainChoice}')

    print("")
    print("Select the Domain to run bundle availability checks:")
    while True:
        ans_file = input("Select Number: ")
        logger.info(f'Input Selection: {ans_file}')
        # If Selection is beyond the list displayed
        if int(ans_file) > count:
            logger.error(f"Invalid selection: {ans_file}")
            continue
        else:
            selection = int(ans_file)
            print(f"\nDomain selected is : {domains[selection][1]} ") 
            logger.info(f"Domain selected is : {domains[selection]}")
            break
    
    return domains[selection][0]

def main(username, password):
    logger.info('Acquiring SDDC Manager Access Token')
    token = gen_token(username, password)
    
    logger.info('Getting SDDC Manager version from localhost/inventory API')
    sddcVersion = getSDDCVersion()
    
    logger.info('Checking for VxRail on VCF')
    IsVxRail = vxrailChecker()
    logger.info('Checking status of File Permissions and Ownership')
    perm_error = permission_ownership_Check(IsVxRail)
    logger.info('Checking status of Services')
    service_error = service_status()    
    
    logger.info('Checking status of Async Patching')
    ap_error = asyncPatching_Check()
    
    logger.info('Checking status of depot connection and configuration')
    checkDepotSettings(token, IsVxRail)
    
    logger.info('Checking status of lcm manifest polling')
    getManifestPolling()
    
    logger.info('Checking migration feature flags')    
    checkMigrationFeatureFlags()
    
    if (perm_error == 1) or (service_error == 1) or (ap_error == 1):
        print(f"\n{CRED}-- Please resolve the errors above and re-try --{CEND}\n")
        logger.error(f'One or more checks failed. Exiting ...')
        sys.exit(1)
        
    
    logger.info('Starting Domain Selection')
    domainId = domainSelector()
    logger.info('Getting all Component versions from localhost/inventory API')
    vcenter,nsxt,host=getBoMVersionsFromAPI(domainId)
    
    logger.info('Loading Manifest')
    manifest = loadManifest(token)
    
    logger.info('Getting Target Versions of BoM Components')
    manifestTargetVersion = getTargetVersions(manifest, sddcVersion)
    
    logger.info('Checking Status of Required Upgrade Bundles and getting previous required versions')
    requiredBundles = getRequiredBundles(manifestTargetVersion, token) 
    
    logger.info('Starting bundle availability logic')
    bundleAvailabilityLogic(requiredBundles,manifestTargetVersion,vcenter,nsxt,host,sddcVersion,token,IsVxRail)
    print()
    logger.info('Execution Complete. Exiting upgradeHelper ...')

if __name__ == '__main__':
    if len(sys.argv) > 2:
        title()
        main(sys.argv[1], sys.argv[2])
    else:
        title()
        logger.debug('No arguements provided. Prompting for username and password.')
        username,password = prompt()
        main(username,password)
