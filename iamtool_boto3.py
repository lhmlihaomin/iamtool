import os
import ConfigParser
import argparse

import boto.iam
import boto3

class AddUserResult(object):
    """Result about add user operation"""
    def __init__(self, username):
        self.username = username
        self.create_user = None     # success: True/False
        self.create_user_msg = ""   # reason if fail
        self.group = {}             # {group_name: result}
        self.group_msg = ""         # reason if fail
        self.password = None        # success: True/False
        self.password_msg = ""      # password if success
        self.access_key = None      # success: True/False
        self.access_key_msg = ""    # "access_key\nsecret_key" if success

def parse_args():
    argparser = argparse.ArgumentParser(description="Manage IAM users.")
    arggroup = argparser.add_mutually_exclusive_group()
    arggroup.add_argument('-a', '--add',
                           help="Tell the script to add users",
                           action="store_true")
    arggroup.add_argument('-d', '--delete',
                           help="Tell the script to remove users",
                           action="store_true")
    argparser.add_argument('-p', '--profiles', 
                           nargs="+", 
                           help=\
"""Add/remove users from profiles listed here. "all" can be used as a
wildcard to perform action on all available profiles.""")
    argparser.add_argument('-u', '--users',
                           nargs="+",
                           help="List of usernames to be added or deleted")
    argparser.add_argument('-g', '--groups',
                           nargs="+",
                           help="Add users to these groups")
    argparser.add_argument('-P', '--create-password', help=\
"""Create password for each user when adding users. Passwords will be saved 
in output files named "<profilename>.<username>.password".
Can only be used with "-a" option.""",
                           action="store_true")
    argparser.add_argument('-A', '--create-access-key', help=\
"""Create access keys for each user when adding users. Access keys will be 
saved in output files named "<profilename>.<username>.accesskey".
Can only be used with "-a" option.""",
                           action="store_true")
    args = argparser.parse_args()
    return args


def get_profile_file_path(profile_name):
    """Get absolute file path for profile config file."""
    filename = "%s.profile.ini"%(profile_name,)
    wd = os.path.dirname(os.path.realpath(__file__))
    # DELETE THIS LINE ON PUBLISH:
    wd += os.path.sep + ".." + os.path.sep
    return os.path.sep.join([wd,filename])


def check_profiles(profiles):
    for profile_name in profiles:
        config_file = get_profile_file_path(profile_name)
        if not os.path.exists(config_file):
            print("ERROR: Profile config '%s' does not exist."%(profile_name))
            return False
    return True


def load_profile(profile_name):
    """Read profile config and connect to IAM service."""
    # read configurations
    config_file = get_profile_file_path(profile_name)
    with open(config_file, 'r') as fp:
        config = ConfigParser.ConfigParser()
        config.readfp(fp)
    access_key = config.get('default', 'aws_access_key_id')
    secret_key = config.get('default', 'aws_secret_access_key')
    region = config.get('default', 'region')
    # connect to IAM service
    iam_conn = boto.iam.connect_to_region(region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key)
    return iam_conn
    


def create_user(iam_conn, username):
    try:
        iam_conn.create_user(username)
        return (True, "")
    except Exception as ex:
        msg = "\n".join([ex.reason, ex.message])
        return (False, msg)


def add_user_to_groups(iam_conn, username, groups):
    result = {}
    for group in groups:
        try:
            iam_conn.add_user_to_group(group, username)
            result.update({group: True})
        except Exception as ex:
            result.update({group: False})
    return result


def default_password(username):
    pd = ""
    if len(username) < 2:
        raise Exception("Username too short")
    pd = username[0:1].upper() \
         + username[1:2].lower() \
         + username[2:] \
         + "@"
    i = 1
    while True:
        pd += str(i)
        i += 1
        if len(pd)>=12:
            break
    return pd


def create_password(iam_conn, username, password):
    iam_conn.create_login_profile(username, password, password_reset_required=True)
    return True
    #try:
    #    iam_conn.create_login_profile(username, password, password_reset_required=True)
    #    return True
    #except Exception as ex:
    #    return False


def create_access_key(iam_conn, username):
    try:
        r = iam_conn.create_access_key(username)
    except:
        return (False, '', '')
    # extract useful info from that super verbose and complicated response:
    access_key = r['create_access_key_response']['create_access_key_result']\
                  ['access_key']['access_key_id']
    secret_key = r['create_access_key_response']['create_access_key_result']\
                  ['access_key']['secret_access_key']
    return (True, access_key, secret_key)


def add_users(profiles,
              usernames,
              groups=[],
              need_password=False,
              need_access_key=False):
    results = []
    for profile in profiles:
        iam_conn = load_profile(profile)
        # For each username:
        for username in usernames:
            result = AddUserResult(username)
            # Create the user:
            result.create_user, result.create_user_msg \
                = create_user(iam_conn, username)
            # Skip following steps if create user failed:
            if not result.create_user:
                continue
            # Add user to groups:
            result.group = add_user_to_groups(iam_conn, username, groups)
            # Set password: 
            if need_password:
                password = default_password(username)
                result.password = create_password(iam_conn, username, password)
                result.password_msg = password
            # Generate access key:
            if need_access_key:
                result.access_key, access_key, secret_key = \
                    create_access_key(iam_conn, username)
                result.access_key_msg = "\n".join([access_key, secret_key])
            results.append(result)
    return results


def delete_users(profiles,
                 users):
    pass


def main():
    args = parse_args()
    profiles = args.profiles
    if profiles is None:
        print("You must provide at least one profile.")
        exit(1)
    usernames = args.users
    if usernames is None:
        print("You must provide at least one username.")
        exit(1)
    if args.add:
        groups = args.groups
        if groups is None:
            groups = []
        need_password = args.create_password
        need_access_key = args.create_access_key
        
        print("Profiles: %s"%(str(profiles),))
        print("Users: %s"%(str(usernames),))
        print("Groups: %s"%(str(groups),))
        print("Create Password: %s"%(str(need_password),))
        print("Create Access_key: %s"%(str(need_access_key),))

        if not check_profiles(profiles):
            exit(1)

        add_users(profiles, usernames, groups, need_password, need_access_key)
    if args.delete:
        print("DELETE")


if __name__ == "__main__":
    main()
