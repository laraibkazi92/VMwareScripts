#!/usr/bin/env python

import ssl
import sys
import os
import pickle
import argparse
import getpass
import atexit
import re

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])

from pyVmomi import SoapStubAdapter, dataservice
from pyVim.connect import SmartConnect, Disconnect

CGREEN = '\033[92m'
CRED = '\033[91m'
CEND = '\033[0m'

__author__ = 'Laraib Kazi | @starlord'

INVSVC_PATH = '/invsvc/vmomi/sdk'
SESSION_MANAGER = 'sessionManager'
AUTHZ_SERVICE = 'authorizationService'

def prompt():
    '''
    Prompts for username and password
    '''
    username = input("Please provide SSO administrator user[administrator@vsphere.local]:")
    if not username:
        username = "administrator@vsphere.local"
    
    # Get password with no echo
    passwd = getpass.getpass("Provide password for %s: " % username)
    return username, passwd

def GetArgs():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(description='Provide the FQDN and select an option to either import or export global permissions \
                    \n | For example: python globalPermissionManager.py -e | python globalPermissionManager.py -i <filename>')
    parser.add_argument('-f', '--fqdn', action='store', required=True, help='FQDN of the node')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--exportSpec', action='store_true', default=False, help='Export all Global Permissions')
    group.add_argument('-i', '--importSpec', action='store', default=False, help='Import all Global Permissions from file')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    return args

def exportPermissions(authz_svc, si):

    access_controls = authz_svc.GetGlobalAccessControlList()
    content = si.RetrieveContent()
    listRoles = content.authorizationManager.roleList
    
    # Regex for Solution Users
    solUser_regex = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"

    GlobalPermissionList=[]
    print(f'\n Exporting Global Permissions : \n')
    for entry in access_controls:
        # Skipping export of solution users
        if re.search(solUser_regex,entry.principal.name):
            entryText = (f'Solution User: {entry.principal.name} ')
            print(f"  [ ! ] Skipping: {entryText}")
        else:
            globalPermission=[]
            globalPermission.append(entry.principal.name)
            globalPermission.append(entry.principal.group)
            globalPermission.append(getRoleName(listRoles,list(entry.roles)))
            globalPermission.append(entry.propagate)
            globalPermission.append(entry.version)
            GlobalPermissionList.append(globalPermission)
            entryText = (f'{CGREEN}User/Group:{CEND} {globalPermission[0]}  |  {CGREEN}Roles:{CEND} {getRoleLabelFromName(listRoles, globalPermission[2])}')
            print(f"  {CGREEN}>{CEND} {entryText}")

    hostname = os.uname()[1]
    with open(f"GlobalPermissionExport_{hostname}.obj", "wb") as exportSpec:
        pickle.dump(GlobalPermissionList, exportSpec)

    print(f"\n All Permissions exported to {CGREEN}GlobalPermissionExport_{hostname}.obj{CEND}\n Please copy/backup this file to use for import operation.\n")

def importPermissions(authz_svc, exportFile, si):

    importSpec = open(exportFile, "rb")
    GlobalPermissionList = pickle.load(importSpec)

    content = si.RetrieveContent()
    listRoles = content.authorizationManager.roleList

    # Regex for Solution Users
    solUser_regex = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"

    # TODO potentially adding additional checks for accounts before import
    print(f'\n Importing Permissions :\n')
    for entry in GlobalPermissionList:
        # Skipping import of solution users
        if re.search(solUser_regex,entry[0]):
            entryText = (f'Solution User: {entry[0]} ')
            print(f"  [ ! ] Skipping: {entryText}")
        else:
            entryText = (f'{CGREEN}User/Group:{CEND} {entry[0]}  |  {CGREEN}Roles:{CEND} {getRoleLabelFromName(listRoles, entry[2])}')
            try:
                principal_spec = dataservice.accesscontrol.Principal(name=entry[0], group=entry[1])
                acl = dataservice.accesscontrol.AccessControl(principal=principal_spec, roles=getRoleIdFromName(listRoles,entry[2]), propagate=entry[3], version=entry[4])
                authz_svc.AddGlobalAccessControlList([acl])
                print(f"  [ {CGREEN}\u2713{CEND} ] {entryText}")
            except:
                print(f"  [ {CRED}\u2717{CEND} ] {entryText}")

    print(f'\n Import operation complete.\n')

def getRoleLabelFromName(listRoles, targetRoleName):
    roleLabels = []
    for role in listRoles:
        if role.name in targetRoleName:
            roleLabels.append(role.info.label)
    return roleLabels

def getRoleName(listRoles, targetRoleId):
    roleNames = []
    for role in listRoles:
        if role.roleId in targetRoleId:
            roleNames.append(role.name)
    return roleNames

def getRoleIdFromName(listRoles, targetRoleName):
    roleIds = []
    for role in listRoles:
        if role.name in targetRoleName:
            roleIds.append(role.roleId)
    return roleIds

def connections():
	
    args = GetArgs()
    host=args.fqdn
    usr, pswd = prompt()

    ssl_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)

    stub = SoapStubAdapter(host, path=INVSVC_PATH,version='dataservice.version.version2',thumbprint=None,sslContext=ssl_ctx,port=443)
    session_mgr = dataservice.authentication.SessionManager(SESSION_MANAGER, stub)
    session_mgr.InventoryServiceLogin(username=usr, password=pswd)
    authz_svc = dataservice.accesscontrol.AuthorizationService(AUTHZ_SERVICE, stub)

    si = SmartConnect(host=host, user=usr, pwd=pswd, port=443, sslContext=ssl._create_unverified_context())

    return authz_svc, stub, si

def main():

    args = GetArgs()
    try:
        authz_svc,stub,si=connections()
    except:
        print(f'\n\tFailed to establish a session.\n\tPlease check your credentials and try again.\n')
        exit(1)
    
    if args.exportSpec:
        exportPermissions(authz_svc, si)
    elif args.importSpec:
        exportFile = args.importSpec
        importPermissions(authz_svc, exportFile, si)
    else:
        print("No arguements specified.")

    if stub:
        stub.DropConnections()
    stub = None
    atexit.register(Disconnect, si)


if __name__ == "__main__":
    main()