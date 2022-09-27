#! /usr/bin/env python

import sys
import os
import getopt
from getpass import getpass
from irods.session import iRODSSession
from irods.access import iRODSAccess

long_options = ["host=", "port=", "zone=", "username=", "password="]
subcommands = ("help", "list_users", "add_user", "change_password")

class BisQueIrodsIntegration:
    def __init__(self, host='localhost', port=1247, admin_user='', password='', zone=''):
        self.host = host
        self.port = port
        self.admin_user = admin_user
        self.password = password
        self.zone = zone


    def set_host(self, host='localhost', port=1247, admin_user='', password='', zone=''):
        self.host = host
        self.port = port
        self.admin_user = admin_user
        self.password = password
        self.zone = zone


    def load_from_env(self):
        host = os.environ.get('BISQUE_IRODS_HOST', '')
        port = 1247
        _port = os.environ.get("BISQUE_IRODS_PORT", '')
        if len(_port) > 0:
            if int(_port) > 0:
                port = int(_port)

        zone = os.environ.get('BISQUE_IRODS_ZONE', '')
        admin_user = os.environ.get('BISQUE_IRODS_ADMIN_USERNAME', '')
        password = os.environ.get('BISQUE_IRODS_ADMIN_PASSWORD', '')

        # verify
        if len(host) == 0:
            raise ValueError("Environment varaible 'BISQUE_IRODS_HOST' is not set")

        if port <= 0:
            raise ValueError("Environment varaible 'BISQUE_IRODS_PORT' is not set")

        if len(zone) == 0:
            raise ValueError("Environment varaible 'BISQUE_IRODS_ZONE' is not set")
        
        if len(admin_user) == 0:
            raise ValueError("Environment varaible 'BISQUE_IRODS_ADMIN_USERNAME' is not set")

        if len(password) == 0:
            raise ValueError("Environment varaible 'BISQUE_IRODS_ADMIN_PASSWORD' is not set")
        
        self.host = host
        self.port = port
        self.zone = zone
        self.admin_user = admin_user
        self.password = password


    def list_users(self):
        # List users
        with iRODSSession(host=self.host, port=self.port, user=self.admin_user, password=self.password, zone=self.zone) as session:
            return session.user_groups.getmembers('bisque_group')


    def create_user(self, new_user='', password=''):
        # Create the user
        # should be done by admin
        with iRODSSession(host=self.host, port=self.port, user=self.admin_user, password=self.password, zone=self.zone) as session:
            # create the user
            # somehow, the password given as 'auth_str' param didn't work, 
            # so had to update password below
            session.users.create(new_user, "rodsuser", self.zone, password)

            # update password
            session.users.modify(new_user, 'password', password, self.zone)


    def update_user_password(self, user='', password=''):
        # Update the user's password
        # should be done by admin
        with iRODSSession(host=self.host, port=self.port, user=self.admin_user, password=self.password, zone=self.zone) as session:
            # update password
            session.users.modify(user, 'password', password, self.zone)


def get_cmd_args(argv):
    host = os.environ.get('BISQUE_IRODS_HOST', '')
    port = 0
    _port = os.environ.get("BISQUE_IRODS_PORT", '')
    if len(_port) > 0:
        if int(_port) > 0:
            port = int(_port)

    zone = os.environ.get('BISQUE_IRODS_ZONE', '')
    admin_user = os.environ.get('BISQUE_IRODS_ADMIN_USERNAME', '')
    password = os.environ.get('BISQUE_IRODS_ADMIN_PASSWORD', '')

    options = ""
    
    try:
        arguments, _ = getopt.getopt(argv, options, long_options)

        for cur_arg, cur_val in arguments:
            if cur_arg in ("--host"):
                host = cur_val
            elif cur_arg in ("--port"):
                port = cur_val
            elif cur_arg in ("--zone"):
                zone = cur_val
            elif cur_arg in ("--username"):
                admin_user = cur_val
            elif cur_arg in ("--password"):
                password = cur_val

    except getopt.error as err:
        sys.stderr.write(str(err) + "\n")
        sys.exit(1)

    if len(host) == 0:
        host = input("iRODS host: ")
        if len(host) == 0:
            sys.stderr.write("iRODS host is not given\n")
            sys.exit(1)

    if port <= 0:
        _port = input("iRODS port [1247]: ")
        if len(_port) > 0:
            if int(_port) > 0:
                port = int(_port)
        else:
            port = 1247

    if len(zone) == 0:
        zone = input("iRODS zone: ")
        if len(zone) == 0:
            sys.stderr.write("iRODS zone is not given\n")
            sys.exit(1)

    if len(host) == 0:
        sys.stderr.write("iRODS host is not given\n")
        sys.exit(1)

    if port <= 0:
        sys.stderr.write("iRODS port is not given\n")
        sys.exit(1)

    if len(zone) == 0:
        sys.stderr.write("iRODS zone is not given\n")
        sys.exit(1)
    
    if len(admin_user) == 0:
        admin_user = input("Admin username: ")
        if len(admin_user) == 0:
            sys.stderr.write("Admin username is not given\n")
            sys.exit(1)

    if len(password) == 0:
        password = getpass(prompt="Admin password: ")
        if len(password) == 0:
            sys.stderr.write("Admin password is not given\n")
            sys.exit(1)

    return {
        "host": host,
        "port": port,
        "admin_user": admin_user,
        "password": password,
        "zone": zone,
    }


def get_sub_cmd(argv):
    if len(argv) == 0:
        return "help"
    else:
        if argv[0] in subcommands:
            return argv[0]

    sys.stderr.write("Unknown subcommand %s" % argv[0])
    return "help"


def get_add_user_param():
    new_user = input("New username: ")
    if len(new_user) == 0:
        sys.stderr.write("New username is not given\n")
        sys.exit(1)

    new_password = getpass(prompt="New user password: ")
    if len(new_password) == 0:
        sys.stderr.write("New user password is not given\n")
        sys.exit(1)

    return {
        "user": new_user,
        "password": new_password,
    }


def get_change_password_param():
    user = input("Username: ")
    if len(user) == 0:
        sys.stderr.write("Username is not given\n")
        sys.exit(1)

    new_password = getpass(prompt="New user password: ")
    if len(new_password) == 0:
        sys.stderr.write("New user password is not given\n")
        sys.exit(1)

    return {
        "user": user,
        "password": new_password,
    }


def main(argv):
    arg = get_cmd_args(argv)
    integ = BisQueIrodsIntegration(host=arg["host"], port=arg["port"], admin_user=arg["admin_user"], password=arg["password"], zone=arg["zone"])

    subcmd = get_sub_cmd(argv)
    if subcmd == "help":
        sys.stdout.write("possible subcommand: %s\n" % str(subcommands))
    elif subcmd == "list_users":
        try:
            users = integ.list_users()
            for user in users:
                sys.stdout.write("- User: %s\n" % user.name)
                sys.stdout.write("  Type: %s\n" % user.type)
        except Exception as err:
            sys.stderr.write(str(err) + "\n")
            sys.stderr.write("failed to list users\n")

    elif subcmd == "add_user":
        try:
            subarg = get_add_user_param()
            integ.create_user(subarg["user"], subarg["password"])
        except Exception as err:
            sys.stderr.write(str(err) + "\n")
            sys.stderr.write("failed to add a new user %s\n" % subarg["user"])

    elif subcmd == "change_password":
        try:
            subarg = get_change_password_param()
            integ.create_user(subarg["user"], subarg["password"])
        except Exception as err:
            sys.stderr.write(str(err) + "\n")
            sys.stderr.write("failed to change the password of user %s\n" % subarg["user"])
    

if __name__ == "__main__":
    main(sys.argv[1:])
    