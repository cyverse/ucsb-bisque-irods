#! /usr/bin/env python3

import sys
from getpass import getpass
from irods.session import iRODSSession
from irods.access import iRODSAccess

class BisQueIrodsIntegration:
    def __init__(self, host='localhost', port=1247, admin_user='', password='', zone=''):
        self.host = host
        self.port = port
        self.admin_user = admin_user
        self.password = password
        self.zone = zone

    def create_user(self, new_user='', password='', groups=[]):
        # Create the user
        # should be done by admin
        with iRODSSession(host=self.host, port=self.port, user=self.admin_user, password=self.password, zone=self.zone) as session:
            # create the user
            # somehow, the password given as 'auth_str' param didn't work, 
            # so had to update password below
            session.users.create(new_user, "rodsuser", self.zone, password)

            # update password
            session.users.modify(new_user, 'password', password, self.zone)

            # add to groups
            for group in groups:
                # we don't need to add the user to 'public' group as it's default
                if group != 'public':
                    session.user_groups.addmember(group, new_user, self.zone)
        
        # Set ACL
        # should be done by the new user 
        self.update_acl_userhome(new_user, password)

    def update_acl_userhome(self, new_user='', password=''):
        # Set ACL
        with iRODSSession(host=self.host, port=self.port, user=new_user, password=password, zone=self.zone) as session:
            userhome = "/%s/home/%s" % (self.zone, new_user)
            
            # enable ACL inheritance of the user's home directory
            acl_inherit = iRODSAccess('inherit', userhome)
            session.permissions.set(acl_inherit)

            # allow rodsadmin group to access the home directory
            acl_admin = iRODSAccess('write', userhome, 'rodsadmin', self.zone)
            session.permissions.set(acl_admin)


def check_args(argv):
    admin_user = ""
    port = 1247
    zone = ""
    if len(argv) == 3:
        host = argv[0]
        port = argv[1]
        zone = argv[2]
    elif len(argv) == 0:
        host = input("iRODS host: ")
        if len(host) == 0:
            print("iRODS host is not given", file=sys.stderr)
            sys.exit(1)

        _port = input("iRODS port [1247]: ")
        if len(_port) > 0:
            if int(_port) > 0:
                port = int(_port)

        zone = input("iRODS zone: ")
        if len(zone) == 0:
            print("iRODS zone is not given", file=sys.stderr)
            sys.exit(1)
    else:
        print("Not sufficient arguments", file=sys.stderr)
        print("> python user.py <host> <port> <zone>", file=sys.stderr)
        sys.exit(1)

    if len(host) == 0:
        print("iRODS host is not given", file=sys.stderr)
        sys.exit(1)

    if port <= 0:
        print("iRODS port is not given", file=sys.stderr)
        sys.exit(1)

    if len(zone) == 0:
        print("iRODS zone is not given", file=sys.stderr)
        sys.exit(1)
    
    admin_user = input("Admin username: ")
    if len(admin_user) == 0:
        print("Admin username is not given", file=sys.stderr)
        sys.exit(1)

    password = getpass(prompt="Admin password: ")
    if len(password) == 0:
        print("Admin password is not given", file=sys.stderr)
        sys.exit(1)
    
    new_user = input("New username: ")
    if len(new_user) == 0:
        print("New username is not given", file=sys.stderr)
        sys.exit(1)

    new_password = getpass(prompt="New user password: ")
    if len(new_password) == 0:
        print("New user password is not given", file=sys.stderr)
        sys.exit(1)


    return {
        "host": host,
        "port": port,
        "admin_user": admin_user,
        "password": password,
        "zone": zone,

        "new_user": new_user,
        "new_password": new_password,
        "groups": ['bisque_group'],
    }

def main(argv):
    arg = check_args(argv)

    integ = BisQueIrodsIntegration(host=arg["host"], port=arg["port"], admin_user=arg["admin_user"], password=arg["password"], zone=arg["zone"])
    integ.create_user(arg["new_user"], arg["new_password"], arg["groups"])

if __name__ == "__main__":
    main(sys.argv[1:])